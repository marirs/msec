//! An APK read end to end: inventory, manifest and resource table, with references resolved.

use std::io::{Read, Seek};

use super::inventory::Inventory;
use super::manifest::Manifest;
use super::resources::ResourceTable;
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
    /// The resource table, when present and readable.
    pub resources: Result<ResourceTable, String>,
    /// App name: the manifest label resolved against the resources.
    pub label: Option<String>,
    /// Version name, resolved when it is a reference.
    pub version_name: Option<String>,
    /// Locales the app's strings are translated into.
    pub locales: Vec<String>,
}

impl Apk {
    /// Reads an APK from an opened archive. Archive anomalies stay on the archive.
    pub fn read<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Self {
        let inventory = Inventory::from_entries(archive.entries());
        let manifest_document = read_entry(archive, MANIFEST_ENTRY)
            .and_then(|bytes| xml::parse(&bytes).map_err(|error| error.to_string()));
        let manifest = manifest_document.as_ref().ok().map(Manifest::from_document);
        let resources = read_entry(archive, RESOURCE_TABLE_ENTRY)
            .and_then(|bytes| ResourceTable::parse(bytes).map_err(|error| error.to_string()));

        let resolve = |value: Option<&Value>| -> Option<String> {
            let value = value?;
            match &resources {
                Ok(table) => table.string(value),
                Err(_) => value.as_str().map(str::to_owned),
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
        let locales = resources
            .as_ref()
            .map(ResourceTable::locales)
            .unwrap_or_default();
        Self {
            inventory,
            manifest_document,
            manifest,
            resources,
            label,
            version_name,
            locales,
        }
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
        let table = self.resources.as_ref().ok()?;
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
