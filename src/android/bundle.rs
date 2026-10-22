//! Android App Bundles (`.aab`): what developers upload to Google Play, which builds the APKs
//! devices install from it. A bundle is a ZIP of modules, each a directory with a protobuf
//! manifest (`<module>/manifest/AndroidManifest.xml`) and its code, native libraries, resources
//! (`resources.pb`) and assets; `BundleConfig.pb` at the root records the bundletool that built
//! it, and `META-INF/` holds the upload key's JAR signature.
//!
//! Every module is read: its manifest, its resource table, its DEX files in load order and its
//! native libraries. The base module is also offered as an [`Apk`] ([`Bundle::base`]) holding
//! the code and libraries of every module, so the APK checks run unchanged; feature modules'
//! manifests are checked with the base module's SDK levels
//! ([`BundleModule::manifest_findings`], [`BundleModule::store_findings`]).

use std::io::{Read, Seek};

use super::analysis::{
    ManifestFinding, NetworkSecurityConfig, StoreFinding, StoreRule, analyse_manifest,
    analyse_store,
};
use super::apk::Apk;
use super::dex::{DexEntry, read_dex_files};
use super::inventory::{Inventory, dex_number};
use super::manifest::Manifest;
use super::native::{NativeLibrary, read_library};
use super::proto::{Fields, ProtoProblem};
use super::resources::ResourceTable;
use super::signing::SigningReport;
use super::value::Value;
use super::xml::{self, XmlDocument, XmlElement, XmlFormat};
use crate::archive::{Entry, ZipArchive};

/// The module every bundle needs: the app itself.
pub const BASE_MODULE: &str = "base";
/// Namespace of the `dist:` elements and attributes that describe a module's delivery.
pub const DISTRIBUTION_NAMESPACE: &str = "http://schemas.android.com/apk/distribution";
/// Where a module keeps its manifest.
const MANIFEST_PATH: &str = "manifest/AndroidManifest.xml";
/// Bundle configuration written by bundletool.
const BUNDLE_CONFIG: &str = "BundleConfig.pb";
/// Root directories that are not modules.
const NON_MODULE_DIRECTORIES: [&str; 2] = ["META-INF", "BUNDLE-METADATA"];

/// What a module is for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ModuleKind {
    /// The `base` module: the app.
    Base,
    /// A feature module (Play Feature Delivery).
    Feature,
    /// An asset pack (Play Asset Delivery): assets only, no code.
    AssetPack,
    /// Another `dist:type`, as written.
    Other(String),
}

/// When Google Play delivers a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delivery {
    /// With the app.
    InstallTime,
    /// With the app, on devices that meet `dist:conditions` (SDK level, features, countries).
    Conditional,
    /// When the app asks for it.
    OnDemand,
    /// Right after installation (asset packs).
    FastFollow,
    /// Not declared: the base module, or a module without `dist:delivery`.
    Unspecified,
}

/// What the module's `dist:module` element declares.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleInfo {
    /// Base, feature or asset pack.
    pub kind: ModuleKind,
    /// When Play delivers it.
    pub delivery: Delivery,
    /// `dist:instant`: part of the instant app.
    pub instant: bool,
    /// `dist:fusing dist:include`: merged into the single APK built for devices that cannot
    /// install split APKs.
    pub fused: Option<bool>,
    /// `dist:title`, usually a string resource reference.
    pub title: Option<Value>,
    /// `split` on `<manifest>`: a feature module's name as its manifest gives it.
    pub split: Option<String>,
}

/// What a module directory contains, counted from entry names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModuleContents {
    /// Files in the module.
    pub files: usize,
    /// `dex/*.dex`.
    pub dex_files: usize,
    /// `lib/<abi>/*.so`.
    pub native_libraries: usize,
    /// ABI directories under `lib/`, sorted.
    pub abis: Vec<String>,
    /// Files under `assets/`.
    pub assets: usize,
    /// `resources.pb` is present.
    pub resource_table: bool,
}

/// One module of a bundle.
#[derive(Debug, Clone)]
pub struct BundleModule {
    /// Directory name (`base`, `camera_feature`).
    pub name: String,
    /// Entry name of its manifest.
    pub manifest_path: String,
    /// Format the manifest is in; bundletool writes protobuf. `None` when unrecognisable.
    pub manifest_format: Option<XmlFormat>,
    /// The decoded manifest document, or why it could not be decoded.
    pub manifest_document: Result<XmlDocument, String>,
    /// The manifest model, when the document decoded.
    pub manifest: Option<Manifest>,
    /// Kind and delivery, from `dist:module`.
    pub info: ModuleInfo,
    /// What the module directory holds.
    pub contents: ModuleContents,
    /// The module's protobuf resource table: `None` without `resources.pb` (asset packs, code
    /// modules without resources), else the table or why it could not be read.
    pub resources: Option<Result<ResourceTable, String>>,
    /// `dex/classes*.dex`, in the order Android loads them.
    pub dex_files: Vec<DexEntry>,
    /// `lib/<abi>/*.so`, parsed, with their hardening. Their place in the bundle's own ZIP says
    /// nothing about the APKs bundletool builds, so they are never marked stored.
    pub native_libraries: Vec<NativeLibrary>,
}

/// `BundleConfig.pb`, as far as msec reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleConfig {
    /// Version of the bundletool that built the bundle.
    pub bundletool_version: Option<String>,
}

/// Something about the bundle's structure worth a look.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BundleProblem {
    /// No `base` module: nothing declares the app.
    NoBaseModule,
    /// A root directory with files but no `manifest/AndroidManifest.xml`.
    DirectoryWithoutManifest(String),
    /// A module manifest in binary XML, the APK format, where bundletool writes protobuf.
    BinaryManifest(String),
    /// A feature module whose manifest `split` differs from its directory name.
    SplitNameMismatch {
        /// Directory name.
        module: String,
        /// `split` in its manifest (`None` when missing).
        split: Option<String>,
    },
    /// `BundleConfig.pb` is missing.
    NoBundleConfig,
    /// `BundleConfig.pb` is not valid protobuf.
    InvalidBundleConfig(ProtoProblem),
}

/// What msec read from an app bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Every module: `base` first, then the others by name.
    pub modules: Vec<BundleModule>,
    /// `BundleConfig.pb`, when present and readable.
    pub config: Option<BundleConfig>,
    /// The upload key's JAR signature (Google Play signs the APKs it serves with the app
    /// signing key instead).
    pub signing: SigningReport,
    /// Structural problems, in the order found.
    pub problems: Vec<BundleProblem>,
    /// The base module seen as an APK, for the checks that read one: its manifest, resource
    /// table and network security configuration, an inventory of its files at the paths they
    /// take in the APK (plus every module's libraries, for the ABIs the app ships), the DEX
    /// files and native libraries of every module (base first, at their bundle paths), and the
    /// bundle's signature. `None` without a base module.
    pub base: Option<Apk>,
}

impl Bundle {
    /// Reads a bundle from an opened archive. Archive anomalies stay on the archive.
    pub fn read<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Self {
        let mut problems = Vec::new();
        let mut modules: Vec<BundleModule> = module_names(archive.entries(), &mut problems)
            .into_iter()
            .map(|name| read_module(archive, name, &mut problems))
            .collect();
        modules.sort_by(|left, right| {
            (left.name != BASE_MODULE, &left.name).cmp(&(right.name != BASE_MODULE, &right.name))
        });
        if !modules.iter().any(|module| module.name == BASE_MODULE) {
            problems.push(BundleProblem::NoBaseModule);
        }
        let config = read_config(archive, &mut problems);
        let signing = SigningReport::read(archive);
        let base = modules
            .iter()
            .position(|module| module.name == BASE_MODULE)
            .map(|index| base_view(archive, &modules, index, &signing));
        Self {
            modules,
            config,
            signing,
            problems,
            base,
        }
    }

    /// Modules other than `base`.
    pub fn non_base_modules(&self) -> impl Iterator<Item = &BundleModule> {
        self.modules
            .iter()
            .filter(|module| module.name != BASE_MODULE)
    }
}

/// Root directories holding a module manifest, plus a problem for each root directory with
/// files but no manifest.
fn module_names(entries: &[Entry], problems: &mut Vec<BundleProblem>) -> Vec<String> {
    let mut with_manifest: Vec<String> = Vec::new();
    let mut directories: Vec<&str> = Vec::new();
    for entry in entries.iter().filter(|entry| !entry.is_directory) {
        let Some((directory, rest)) = entry.name.split_once('/') else {
            continue;
        };
        if NON_MODULE_DIRECTORIES.contains(&directory) || directory.is_empty() {
            continue;
        }
        if !directories.contains(&directory) {
            directories.push(directory);
        }
        if rest == MANIFEST_PATH && !with_manifest.iter().any(|name| name == directory) {
            with_manifest.push(directory.to_owned());
        }
    }
    for directory in directories {
        if !with_manifest.iter().any(|name| name == directory) {
            problems.push(BundleProblem::DirectoryWithoutManifest(
                directory.to_owned(),
            ));
        }
    }
    with_manifest
}

fn read_module<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: String,
    problems: &mut Vec<BundleProblem>,
) -> BundleModule {
    let manifest_path = format!("{name}/{MANIFEST_PATH}");
    let bytes = archive
        .read_by_name(&manifest_path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| bytes.ok_or_else(|| format!("{manifest_path} not found")));
    let manifest_format = bytes.as_deref().ok().and_then(XmlFormat::detect);
    if manifest_format == Some(XmlFormat::Binary) {
        problems.push(BundleProblem::BinaryManifest(name.clone()));
    }
    // A binary manifest is still read: what it declares matters either way.
    let manifest_document = bytes.and_then(|bytes| {
        match manifest_format {
            Some(XmlFormat::Binary) => xml::parse(&bytes),
            _ => xml::parse_proto(&bytes),
        }
        .map_err(|error| error.to_string())
    });
    let manifest = manifest_document.as_ref().ok().map(Manifest::from_document);
    let info = manifest_document
        .as_ref()
        .ok()
        .and_then(|document| document.root.as_ref())
        .map_or_else(
            || ModuleInfo::default_for(&name),
            |root| module_info(root, &name),
        );
    if info.kind == ModuleKind::Feature && info.split.as_deref() != Some(name.as_str()) {
        problems.push(BundleProblem::SplitNameMismatch {
            module: name.clone(),
            split: info.split.clone(),
        });
    }
    let contents = module_contents(archive.entries(), &name);
    let resources = contents.resource_table.then(|| {
        read(archive, &format!("{name}/resources.pb"))
            .and_then(|bytes| ResourceTable::parse_proto(&bytes).map_err(|error| error.to_string()))
    });
    let dex_names = module_dex_names(archive.entries(), &name);
    let dex_files = read_dex_files(archive, &dex_names);
    let native_libraries = read_module_libraries(archive, &name);
    BundleModule {
        name,
        manifest_path,
        manifest_format,
        manifest_document,
        manifest,
        info,
        contents,
        resources,
        dex_files,
        native_libraries,
    }
}

fn read<R: Read + Seek>(archive: &mut ZipArchive<R>, name: &str) -> Result<Vec<u8>, String> {
    archive
        .read_by_name(name)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("{name} not found"))
}

/// `<module>/dex/classes*.dex` in load order (`classes.dex`, `classes2.dex`, ...); bundletool
/// names a module's DEX files this way.
fn module_dex_names(entries: &[Entry], module: &str) -> Vec<String> {
    let prefix = format!("{module}/dex/");
    let mut names: Vec<(u32, String)> = entries
        .iter()
        .filter(|entry| !entry.is_directory)
        .filter_map(|entry| {
            let file = entry.name.strip_prefix(&prefix)?;
            (!file.contains('/') && file.starts_with("classes") && file.ends_with(".dex"))
                .then(|| (dex_number(file), entry.name.clone()))
        })
        .collect();
    names.sort();
    names.dedup();
    names.into_iter().map(|(_, name)| name).collect()
}

/// `<module>/lib/<abi>/*.so`, each parsed.
fn read_module_libraries<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    module: &str,
) -> Vec<NativeLibrary> {
    let prefix = format!("{module}/lib/");
    let candidates: Vec<(usize, String, String, u64)> = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory)
        .filter_map(|entry| {
            let (abi, file) = entry.name.strip_prefix(&prefix)?.split_once('/')?;
            (file.ends_with(".so") && !file.contains('/')).then(|| {
                (
                    entry.index,
                    entry.name.clone(),
                    abi.to_owned(),
                    entry.uncompressed_size,
                )
            })
        })
        .collect();
    candidates
        .into_iter()
        .map(|(index, path, abi, size)| {
            // The bundle's ZIP layout is not the APK's: never "stored", no data offset.
            read_library(archive, index, path, Some(abi), false, None, size)
        })
        .collect()
}

impl ModuleInfo {
    fn default_for(name: &str) -> Self {
        Self {
            kind: if name == BASE_MODULE {
                ModuleKind::Base
            } else {
                ModuleKind::Feature
            },
            delivery: Delivery::Unspecified,
            instant: false,
            fused: None,
            title: None,
            split: None,
        }
    }
}

/// Kind and delivery from `<dist:module>`. bundletool reads `dist:type` (default `feature`),
/// the `dist:delivery` element, and the older `dist:onDemand` attribute it replaced.
fn module_info(root: &XmlElement, name: &str) -> ModuleInfo {
    let mut info = ModuleInfo::default_for(name);
    info.split = root
        .plain_attribute("split")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let Some(module) = distribution_child(root, "module") else {
        return info;
    };
    if name != BASE_MODULE {
        info.kind = match distribution_attribute(module, "type").and_then(Value::as_str) {
            None | Some("feature") => ModuleKind::Feature,
            Some("asset-pack") => ModuleKind::AssetPack,
            Some(other) => ModuleKind::Other(other.to_owned()),
        };
    }
    info.instant = distribution_attribute(module, "instant")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    info.title = distribution_attribute(module, "title").cloned();
    info.fused = distribution_child(module, "fusing")
        .and_then(|fusing| distribution_attribute(fusing, "include"))
        .and_then(Value::as_bool);
    let legacy_on_demand = distribution_attribute(module, "onDemand").and_then(Value::as_bool);
    info.delivery = match distribution_child(module, "delivery") {
        Some(delivery) => delivery_of(delivery),
        None if legacy_on_demand == Some(true) => Delivery::OnDemand,
        None if legacy_on_demand == Some(false) => Delivery::InstallTime,
        None => Delivery::Unspecified,
    };
    info
}

fn delivery_of(delivery: &XmlElement) -> Delivery {
    if let Some(install_time) = distribution_child(delivery, "install-time") {
        return if distribution_child(install_time, "conditions").is_some() {
            Delivery::Conditional
        } else {
            Delivery::InstallTime
        };
    }
    if distribution_child(delivery, "fast-follow").is_some() {
        return Delivery::FastFollow;
    }
    if distribution_child(delivery, "on-demand").is_some() {
        return Delivery::OnDemand;
    }
    Delivery::Unspecified
}

fn distribution_child<'element>(
    element: &'element XmlElement,
    name: &str,
) -> Option<&'element XmlElement> {
    element.elements().find(|child| {
        child.name == name && child.namespace.as_deref() == Some(DISTRIBUTION_NAMESPACE)
    })
}

fn distribution_attribute<'element>(
    element: &'element XmlElement,
    name: &str,
) -> Option<&'element Value> {
    element
        .attributes
        .iter()
        .find(|attribute| {
            attribute.name == name && attribute.namespace.as_deref() == Some(DISTRIBUTION_NAMESPACE)
        })
        .map(|attribute| &attribute.value)
}

fn module_contents(entries: &[Entry], module: &str) -> ModuleContents {
    let prefix = format!("{module}/");
    let mut contents = ModuleContents::default();
    for entry in entries.iter().filter(|entry| !entry.is_directory) {
        let Some(path) = entry.name.strip_prefix(&prefix) else {
            continue;
        };
        contents.files += 1;
        if let Some(name) = path.strip_prefix("dex/") {
            if name.ends_with(".dex") && !name.contains('/') {
                contents.dex_files += 1;
            }
        } else if let Some(rest) = path.strip_prefix("lib/") {
            if let Some((abi, file)) = rest.split_once('/')
                && file.ends_with(".so")
                && !file.contains('/')
            {
                contents.native_libraries += 1;
                if !contents.abis.iter().any(|known| known == abi) {
                    contents.abis.push(abi.to_owned());
                }
            }
        } else if path.starts_with("assets/") {
            contents.assets += 1;
        } else if path == "resources.pb" {
            contents.resource_table = true;
        }
    }
    contents.abis.sort();
    contents
}

/// `BundleConfig.pb`: `bundletool` (field 1) holds `version` (field 2).
fn read_config<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    problems: &mut Vec<BundleProblem>,
) -> Option<BundleConfig> {
    let Ok(Some(bytes)) = archive.read_by_name(BUNDLE_CONFIG) else {
        problems.push(BundleProblem::NoBundleConfig);
        return None;
    };
    match parse_config(&bytes) {
        Ok(config) => Some(config),
        Err(problem) => {
            problems.push(BundleProblem::InvalidBundleConfig(problem));
            None
        }
    }
}

fn parse_config(bytes: &[u8]) -> Result<BundleConfig, ProtoProblem> {
    let mut config = BundleConfig {
        bundletool_version: None,
    };
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        if number != 1 {
            continue;
        }
        for field in Fields::new(value.bytes()?) {
            let (number, value) = field?;
            if number == 2 {
                config.bundletool_version = Some(value.string()?.to_owned());
            }
        }
    }
    Ok(config)
}

/// The base module as an APK (see [`Bundle::base`]): its manifest and resources, its network
/// security configuration (protobuf XML, as bundletool stores `res/xml` files), an inventory of
/// its files at their APK paths plus every module's libraries (for the ABIs the app ships), and
/// the DEX files and native libraries of every module, base first.
fn base_view<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    modules: &[BundleModule],
    base_index: usize,
    signing: &SigningReport,
) -> Apk {
    let module = &modules[base_index];
    let apk_entries: Vec<Entry> = archive
        .entries()
        .iter()
        .filter_map(|entry| {
            let (directory, path) = entry.name.split_once('/')?;
            let is_module = modules.iter().any(|module| module.name == directory);
            let keep = directory == BASE_MODULE || (is_module && path.starts_with("lib/"));
            keep.then(|| {
                let mut mapped = entry.clone();
                mapped.name = apk_path(path);
                mapped
            })
        })
        .collect();
    let mut apk = Apk {
        inventory: Inventory::from_entries(&apk_entries),
        manifest_document: module.manifest_document.clone(),
        manifest: module.manifest.clone(),
        resources: module.resources.clone(),
        label: None,
        version_name: None,
        locales: Vec::new(),
        network_security_config: None,
        backup_rules: Vec::new(),
        signing: signing.clone(),
        native_libraries: modules
            .iter()
            .flat_map(|module| module.native_libraries.iter().cloned())
            .collect(),
        dex_files: modules
            .iter()
            .flat_map(|module| module.dex_files.iter().cloned())
            .collect(),
    };
    apk.resolve_identity();
    apk.network_security_config = apk.network_security_config_declared().then(|| {
        let path = apk
            .network_security_config_path()
            .ok_or("the configuration does not resolve to a file")?;
        let bytes = read(archive, &format!("{BASE_MODULE}/{path}"))?;
        let document = match XmlFormat::detect(&bytes) {
            Some(XmlFormat::Binary) => xml::parse(&bytes),
            _ => xml::parse_proto(&bytes),
        }
        .map_err(|error| error.to_string())?;
        Ok(NetworkSecurityConfig::from_document(
            &document,
            apk.resource_table(),
        ))
    });
    apk.backup_rules = apk.read_backup_rules(|path| {
        let bytes = read(archive, &format!("{BASE_MODULE}/{path}"))?;
        match XmlFormat::detect(&bytes) {
            Some(XmlFormat::Binary) => xml::parse(&bytes),
            _ => xml::parse_proto(&bytes),
        }
        .map_err(|error| error.to_string())
    });
    apk
}

impl BundleModule {
    /// This module's manifest with the base module's SDK levels and package, which feature
    /// manifests do not repeat (Android applies the base's to every split). `None` for the
    /// base module and for modules whose manifest did not decode.
    fn manifest_in_app(&self, base: &Manifest) -> Option<Manifest> {
        if self.name == BASE_MODULE {
            return None;
        }
        let mut manifest = self.manifest.clone()?;
        manifest.min_sdk_version = base.min_sdk_version.clone();
        manifest.target_sdk_version = base.target_sdk_version.clone();
        if manifest.package.is_none() {
            manifest.package = base.package.clone();
        }
        Some(manifest)
    }

    /// Findings about the components this module declares, checked as part of the app (the
    /// base module's SDK levels decide export defaults). App-wide settings are the base
    /// manifest's, so findings without a component are left out. Empty for the base module.
    pub fn manifest_findings(&self, base: &Manifest) -> Vec<ManifestFinding> {
        let Some(manifest) = self.manifest_in_app(base) else {
            return Vec::new();
        };
        analyse_manifest(&manifest, None)
            .into_iter()
            .filter(|finding| finding.component.is_some())
            .collect()
    }

    /// Store findings about what this module declares: permissions Play restricts and
    /// foreground service types. App-wide checks (target API, package name, versionCode, 64-bit
    /// code) are the base module's. Empty for the base module.
    pub fn store_findings(&self, base: &Manifest, today: &str) -> Vec<StoreFinding> {
        let Some(manifest) = self.manifest_in_app(base) else {
            return Vec::new();
        };
        let declarations = [
            StoreRule::RestrictedPermission,
            StoreRule::ForegroundServicePermissionMissing,
            StoreRule::ForegroundServiceTypeMissing,
        ];
        analyse_store(&manifest, &Inventory::from_entries(&[]), today)
            .into_iter()
            .filter(|finding| declarations.contains(&finding.rule))
            .collect()
    }
}

/// Where a module file lands in the APK bundletool builds: `dex/` and `root/` files at the APK
/// root, the manifest at `AndroidManifest.xml`, everything else (lib/, assets/, res/) as is.
fn apk_path(path: &str) -> String {
    if path == MANIFEST_PATH {
        return "AndroidManifest.xml".to_owned();
    }
    path.strip_prefix("dex/")
        .or_else(|| path.strip_prefix("root/"))
        .unwrap_or(path)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_files_land_where_bundletool_puts_them() {
        assert_eq!(apk_path("dex/classes2.dex"), "classes2.dex");
        assert_eq!(
            apk_path("root/kotlin/kotlin.kotlin_builtins"),
            "kotlin/kotlin.kotlin_builtins"
        );
        assert_eq!(
            apk_path("manifest/AndroidManifest.xml"),
            "AndroidManifest.xml"
        );
        assert_eq!(
            apk_path("lib/arm64-v8a/libapp.so"),
            "lib/arm64-v8a/libapp.so"
        );
        assert_eq!(apk_path("assets/data.bin"), "assets/data.bin");
    }

    #[test]
    fn bundle_config_names_the_bundletool_version() {
        // BundleConfig { bundletool { version: "1.18.1" } }
        let bytes = [0x0a, 0x08, 0x12, 0x06, b'1', b'.', b'1', b'8', b'.', b'1'];
        assert_eq!(
            parse_config(&bytes),
            Ok(BundleConfig {
                bundletool_version: Some("1.18.1".into())
            })
        );
        assert_eq!(
            parse_config(&[0x0a, 0x09]),
            Err(ProtoProblem::LengthPastEnd)
        );
    }
}
