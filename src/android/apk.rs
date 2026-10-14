//! An APK read end to end: inventory, manifest and resource table, with references resolved.

use std::io::{Read, Seek};

use super::analysis::{
    ManifestFinding, NativeFinding, NetworkFinding, NetworkSecurityConfig, SigningFinding,
    StoreFinding, analyse_manifest, analyse_native, analyse_network_security, analyse_signing,
    analyse_store,
};
use super::dex::{CodeSummary, DexEntry, read_dex_files, summarise};
use super::inventory::Inventory;
use super::manifest::Manifest;
use super::native::{NativeLibrary, read_native_libraries};
use super::resources::ResourceTable;
use super::signing::SigningReport;
use super::value::Value;
use super::xml::{self, XmlDocument};
use crate::archive::ZipArchive;

const MANIFEST_ENTRY: &str = "AndroidManifest.xml";
const RESOURCE_TABLE_ENTRY: &str = "resources.arsc";

/// What msec read from an APK. Parts that could not be read carry the reason instead, so one
/// broken part never hides the others.
#[derive(Debug, Clone)]
pub struct Apk {
    /// Composition, ABIs, frameworks.
    pub inventory: Inventory,
    /// The decoded manifest document (anomalies, text rendering).
    pub manifest_document: Result<XmlDocument, String>,
    /// The manifest model, when the document decoded.
    pub manifest: Option<Manifest>,
    /// The resource table: `None` when the APK has none (valid, if unusual), else the table or
    /// why it could not be read.
    pub resources: Option<Result<ResourceTable, String>>,
    /// App name: the manifest label resolved against the resources.
    pub label: Option<String>,
    /// Version name, resolved when it is a reference.
    pub version_name: Option<String>,
    /// Locales the app's strings are translated into.
    pub locales: Vec<String>,
    /// The network security configuration: `None` when the manifest names none, else the
    /// decoded configuration or why it could not be read. Only the file the manifest names is
    /// read, as on Android.
    pub network_security_config: Option<Result<NetworkSecurityConfig, String>>,
    /// Signatures, verified.
    pub signing: SigningReport,
    /// Every `.so` in the APK, parsed, with its hardening.
    pub native_libraries: Vec<NativeLibrary>,
    /// The root `classes*.dex` files, in the order Android loads them.
    pub dex_files: Vec<DexEntry>,
}

impl Apk {
    /// Reads an APK from an opened archive. Archive anomalies stay on the archive.
    pub fn read<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Self {
        let inventory = Inventory::from_entries(archive.entries());
        let manifest_document = read_entry(archive, MANIFEST_ENTRY)
            .and_then(|bytes| xml::parse(&bytes).map_err(|error| error.to_string()));
        let manifest = manifest_document.as_ref().ok().map(Manifest::from_document);
        let resources = archive.find(RESOURCE_TABLE_ENTRY).is_some().then(|| {
            read_entry(archive, RESOURCE_TABLE_ENTRY)
                .and_then(|bytes| ResourceTable::parse(bytes).map_err(|error| error.to_string()))
        });
        let table = resources.as_ref().and_then(|result| result.as_ref().ok());

        let resolve = |value: Option<&Value>| -> Option<String> {
            let value = value?;
            match table {
                Some(table) => table.string(value),
                None => value.as_str().map(str::to_owned),
            }
        };
        let application = manifest
            .as_ref()
            .and_then(|manifest| manifest.application.as_ref());
        let label = resolve(application.and_then(|application| application.label.as_ref()));
        let version_name = resolve(
            manifest
                .as_ref()
                .and_then(|manifest| manifest.version_name.as_ref()),
        );
        let locales = table.map(ResourceTable::locales).unwrap_or_default();
        let mut apk = Self {
            inventory,
            manifest_document,
            manifest,
            resources,
            label,
            version_name,
            locales,
            network_security_config: None,
            signing: SigningReport::read(archive),
            native_libraries: read_native_libraries(archive),
            dex_files: Vec::new(),
        };
        apk.dex_files = read_dex_files(archive, &apk.inventory.dex_files);
        apk.network_security_config = apk.read_network_security_config(archive);
        apk
    }

    fn read_network_security_config<R: Read + Seek>(
        &self,
        archive: &mut ZipArchive<R>,
    ) -> Option<Result<NetworkSecurityConfig, String>> {
        let declared = self
            .manifest
            .as_ref()?
            .application
            .as_ref()?
            .network_security_config
            .as_ref()?;
        let Some(path) = self.network_security_config_path() else {
            return Some(Err(format!("{declared} does not resolve to a file")));
        };
        Some(read_entry(archive, &path).and_then(|bytes| {
            let document = xml::parse(&bytes).map_err(|error| error.to_string())?;
            Ok(NetworkSecurityConfig::from_document(
                &document,
                self.resource_table(),
            ))
        }))
    }

    /// `@xml/name` for the configured network security configuration.
    pub fn network_security_config_name(&self) -> Option<String> {
        let reference = self
            .manifest
            .as_ref()?
            .application
            .as_ref()?
            .network_security_config
            .as_ref()?;
        let name = reference
            .reference()
            .and_then(|id| self.resource_table()?.name(id));
        Some(name.map_or_else(
            || reference.to_string(),
            |name| format!("@{}/{}", name.type_name, name.entry),
        ))
    }

    /// Manifest security findings; empty when the manifest could not be read.
    pub fn manifest_findings(&self) -> Vec<ManifestFinding> {
        self.manifest.as_ref().map_or_else(Vec::new, |manifest| {
            analyse_manifest(manifest, self.network_security_config_name().as_deref())
        })
    }

    /// Signing findings; `today` (`yyyy-MM-dd`) dates certificate expiry. Without a readable
    /// manifest, Android's defaults (minimum and target API 1) apply.
    pub fn signing_findings(&self, today: &str) -> Vec<SigningFinding> {
        let manifest = self.manifest.as_ref();
        let min_sdk = manifest.and_then(Manifest::min_sdk).unwrap_or(1);
        let target_sdk = manifest.and_then(Manifest::target_sdk).unwrap_or(min_sdk);
        analyse_signing(&self.signing, min_sdk, target_sdk, today)
    }

    /// What the DEX files hold together: classes, packages, shadowed classes.
    pub fn code_summary(&self) -> CodeSummary {
        summarise(&self.dex_files)
    }

    /// Native library findings.
    pub fn native_findings(&self) -> Vec<NativeFinding> {
        analyse_native(&self.native_libraries)
    }

    /// Google Play store-readiness findings; `today` (`yyyy-MM-dd`) picks the target API
    /// requirement in force. Empty when the manifest could not be decoded.
    pub fn store_findings(&self, today: &str) -> Vec<StoreFinding> {
        self.manifest
            .as_ref()
            .map(|manifest| analyse_store(manifest, &self.inventory, today))
            .unwrap_or_default()
    }

    /// Network security configuration findings, with expiry dates compared to `today`
    /// (`yyyy-MM-dd`). Empty when there is no readable configuration.
    pub fn network_findings(&self, today: &str) -> Vec<NetworkFinding> {
        let Some(Ok(config)) = &self.network_security_config else {
            return Vec::new();
        };
        let debuggable = self
            .manifest
            .as_ref()
            .and_then(|manifest| manifest.application.as_ref())
            .and_then(|application| application.debuggable)
            == Some(true);
        analyse_network_security(config, debuggable, today)
    }

    /// The resource table, when present and readable.
    pub fn resource_table(&self) -> Option<&ResourceTable> {
        self.resources.as_ref()?.as_ref().ok()
    }

    /// Path of the network security configuration file, when the manifest points to one.
    pub fn network_security_config_path(&self) -> Option<String> {
        let reference = self
            .manifest
            .as_ref()?
            .application
            .as_ref()?
            .network_security_config
            .as_ref()?;
        let table = self.resource_table()?;
        let files = table.files(reference.reference()?);
        files
            .iter()
            .find(|(config, _)| config.is_default())
            .or_else(|| files.first())
            .map(|(_, path)| path.clone())
    }
}

fn read_entry<R: Read + Seek>(archive: &mut ZipArchive<R>, name: &str) -> Result<Vec<u8>, String> {
    archive
        .read_by_name(name)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("{name} not found"))
}
