//! Android decoders against crafted and mutated input: obfuscation tricks are seen through the
//! way Android sees through them, malformed structure is reported, and nothing panics.

use std::io::Cursor;

use msec::android::manifest::Manifest;
use msec::android::xml::{self, ANDROID_NAMESPACE, MalformedNode, XmlAnomalyKind, XmlError};
use msec::android::{ResourceTable, Value};
use msec::archive::{Limits, ZipArchive};

const BASIC_APK: &[u8] = include_bytes!("fixtures/android/basic.apk");

const MIN_SDK_VERSION: u32 = 0x0101_020c;
const TARGET_SDK_VERSION: u32 = 0x0101_0270;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_STRING: u8 = 0x03;
const NO_STRING: u32 = u32::MAX;

/// Writes binary XML by hand. Strings that carry resource IDs come first in the pool, as aapt2
/// lays them out, so string index N maps to `resource_ids[N]`.
struct AxmlWriter {
    strings: Vec<String>,
    resource_ids: Vec<u32>,
    nodes: Vec<u8>,
    /// Extra chunks written before the string pool.
    prologue_extra: Vec<u8>,
}

struct Attribute {
    namespace: Option<u32>,
    name: u32,
    data_type: u8,
    data: u32,
}

impl AxmlWriter {
    fn new(attributes_with_ids: &[(&str, u32)]) -> Self {
        Self {
            strings: attributes_with_ids
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect(),
            resource_ids: attributes_with_ids.iter().map(|(_, id)| *id).collect(),
            nodes: Vec::new(),
            prologue_extra: Vec::new(),
        }
    }

    fn string(&mut self, text: &str) -> u32 {
        if let Some(index) = self
            .strings
            .iter()
            .skip(self.resource_ids.len())
            .position(|s| s == text)
        {
            return (index + self.resource_ids.len()) as u32;
        }
        self.strings.push(text.to_owned());
        (self.strings.len() - 1) as u32
    }

    fn node(&mut self, kind: u16, extension: &[u8]) {
        self.nodes.extend_from_slice(&kind.to_le_bytes());
        self.nodes.extend_from_slice(&16u16.to_le_bytes());
        self.nodes
            .extend_from_slice(&((16 + extension.len()) as u32).to_le_bytes());
        self.nodes.extend_from_slice(&1u32.to_le_bytes());
        self.nodes.extend_from_slice(&NO_STRING.to_le_bytes());
        self.nodes.extend_from_slice(extension);
    }

    fn start_namespace(&mut self) {
        let (prefix, uri) = (self.string("android"), self.string(ANDROID_NAMESPACE));
        self.node(0x0100, &[prefix.to_le_bytes(), uri.to_le_bytes()].concat());
    }

    fn start(&mut self, name: &str, attributes: &[Attribute]) {
        let name = self.string(name);
        let mut extension = Vec::new();
        extension.extend_from_slice(&NO_STRING.to_le_bytes());
        extension.extend_from_slice(&name.to_le_bytes());
        for field in [20u16, 20, attributes.len() as u16, 0, 0, 0] {
            extension.extend_from_slice(&field.to_le_bytes());
        }
        for attribute in attributes {
            extension.extend_from_slice(&attribute.namespace.unwrap_or(NO_STRING).to_le_bytes());
            extension.extend_from_slice(&attribute.name.to_le_bytes());
            let raw = if attribute.data_type == TYPE_STRING {
                attribute.data
            } else {
                NO_STRING
            };
            extension.extend_from_slice(&raw.to_le_bytes());
            extension.extend_from_slice(&8u16.to_le_bytes());
            extension.push(0);
            extension.push(attribute.data_type);
            extension.extend_from_slice(&attribute.data.to_le_bytes());
        }
        self.node(0x0102, &extension);
    }

    fn end(&mut self, name: &str) {
        let name = self.string(name);
        self.node(
            0x0103,
            &[NO_STRING.to_le_bytes(), name.to_le_bytes()].concat(),
        );
    }

    /// A chunk of any type in the node area. Android needs a full 16-byte node header there.
    fn raw_node(&mut self, kind: u16, body: &[u8]) {
        self.node(kind, body);
    }

    fn finish(&self) -> Vec<u8> {
        let pool = string_pool(&self.strings);
        let mut map = Vec::new();
        map.extend_from_slice(&0x0180u16.to_le_bytes());
        map.extend_from_slice(&8u16.to_le_bytes());
        map.extend_from_slice(&((8 + self.resource_ids.len() * 4) as u32).to_le_bytes());
        for id in &self.resource_ids {
            map.extend_from_slice(&id.to_le_bytes());
        }
        let body = [self.prologue_extra.clone(), pool, map, self.nodes.clone()].concat();
        let mut document = Vec::new();
        document.extend_from_slice(&0x0003u16.to_le_bytes());
        document.extend_from_slice(&8u16.to_le_bytes());
        document.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        document.extend_from_slice(&body);
        document
    }

    /// `<manifest package="p"><uses-sdk .../></manifest>` with the given uses-sdk attributes.
    fn manifest_with_uses_sdk(
        mut self,
        uses_sdk: impl FnOnce(&mut Self) -> Vec<Attribute>,
    ) -> Vec<u8> {
        self.start_namespace();
        let package_name = self.string("package");
        let package_value = self.string("com.example.trick");
        self.start(
            "manifest",
            &[Attribute {
                namespace: None,
                name: package_name,
                data_type: TYPE_STRING,
                data: package_value,
            }],
        );
        let attributes = uses_sdk(&mut self);
        self.start("uses-sdk", &attributes);
        self.end("uses-sdk");
        self.end("manifest");
        self.finish()
    }
}

/// UTF-16 string pool chunk.
fn string_pool(strings: &[String]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for string in strings {
        offsets.push(data.len() as u32);
        let units: Vec<u16> = string.encode_utf16().collect();
        data.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for unit in units {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let strings_start = 28 + offsets.len() * 4;
    let mut chunk = Vec::new();
    for value in [0x0001u16, 28] {
        chunk.extend_from_slice(&value.to_le_bytes());
    }
    for value in [
        (strings_start + data.len()) as u32,
        strings.len() as u32,
        0,
        0,
        strings_start as u32,
        0,
    ] {
        chunk.extend_from_slice(&value.to_le_bytes());
    }
    for offset in offsets {
        chunk.extend_from_slice(&offset.to_le_bytes());
    }
    chunk.extend_from_slice(&data);
    chunk
}

fn kinds(bytes: &[u8]) -> Vec<XmlAnomalyKind> {
    xml::parse(bytes)
        .unwrap()
        .anomalies
        .into_iter()
        .map(|anomaly| anomaly.kind)
        .collect()
}

#[test]
fn renamed_attribute_strings_are_resolved_by_resource_id_like_android() {
    // The pool says "versionName" but the resource map says minSdkVersion: Android reads 21
    // as the minimum SDK; a name-based tool would report a version name.
    let bytes =
        AxmlWriter::new(&[("versionName", MIN_SDK_VERSION)]).manifest_with_uses_sdk(|writer| {
            let namespace = writer.string(ANDROID_NAMESPACE);
            vec![Attribute {
                namespace: Some(namespace),
                name: 0,
                data_type: TYPE_INT_DEC,
                data: 21,
            }]
        });
    let document = xml::parse(&bytes).unwrap();
    assert_eq!(Manifest::from_document(&document).min_sdk(), Some(21));
    assert!(document.anomalies.iter().any(|anomaly| anomaly.kind
        == XmlAnomalyKind::AttributeNameMismatch {
            resolved: "minSdkVersion".into(),
            written: "versionName".into()
        }));
    assert!(document.to_xml().contains("android:minSdkVersion=\"21\""));
}

#[test]
fn android_attributes_without_resource_ids_are_ignored_like_android() {
    // targetSdkVersion has a resource ID; the unmapped "minSdkVersion" string does not, so
    // Android ignores it and the minimum SDK stays at its default of 1.
    let bytes = AxmlWriter::new(&[("targetSdkVersion", TARGET_SDK_VERSION)])
        .manifest_with_uses_sdk(|writer| {
            let namespace = writer.string(ANDROID_NAMESPACE);
            let unmapped = writer.string("minSdkVersion");
            vec![
                Attribute {
                    namespace: Some(namespace),
                    name: 0,
                    data_type: TYPE_INT_DEC,
                    data: 34,
                },
                Attribute {
                    namespace: Some(namespace),
                    name: unmapped,
                    data_type: TYPE_INT_DEC,
                    data: 30,
                },
            ]
        });
    let document = xml::parse(&bytes).unwrap();
    let manifest = Manifest::from_document(&document);
    assert_eq!(
        (manifest.min_sdk(), manifest.target_sdk()),
        (Some(1), Some(34))
    );
    assert!(document.anomalies.iter().any(|anomaly| anomaly.kind
        == XmlAnomalyKind::UnresolvedAndroidAttribute {
            name: "minSdkVersion".into()
        }));
}

#[test]
fn the_last_string_pool_wins_like_android() {
    let mut writer = AxmlWriter::new(&[]);
    writer.prologue_extra =
        string_pool(&["decoy".to_owned(), "decoy".to_owned(), "decoy".to_owned()]);
    let bytes = writer.manifest_with_uses_sdk(|_| Vec::new());
    let document = xml::parse(&bytes).unwrap();
    assert!(
        document
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == XmlAnomalyKind::MultipleStringPools)
    );
    // The decoy pool comes first and the real one last, so names resolve as Android sees them.
    assert_eq!(document.root.unwrap().name, "manifest");
}

#[test]
fn short_node_headers_stop_the_document_like_android() {
    let mut writer = AxmlWriter::new(&[]);
    writer.start_namespace();
    writer.start("manifest", &[]);
    // ResXMLParser validates every chunk in the node area against the 16-byte node header.
    writer.nodes.extend_from_slice(&0x0177u16.to_le_bytes());
    writer.nodes.extend_from_slice(&8u16.to_le_bytes());
    writer.nodes.extend_from_slice(&16u32.to_le_bytes());
    writer.nodes.extend_from_slice(&[0; 8]);
    writer.start("application", &[]);
    let found = kinds(&writer.finish());
    assert!(
        found.contains(&XmlAnomalyKind::MalformedNode(MalformedNode::Chunk(
            msec::android::ChunkProblem::HeaderTooSmall
        )))
    );
}

#[test]
fn malformed_attribute_blocks_stop_the_document_like_android() {
    let mut bytes = AxmlWriter::new(&[]).manifest_with_uses_sdk(|_| Vec::new());
    // The uses-sdk start element is the third node; claim 0xffff attributes on it.
    let position = find_node(&bytes, 0x0102, 1);
    bytes[position + 16 + 12..position + 16 + 14].copy_from_slice(&0xffffu16.to_le_bytes());
    let document = xml::parse(&bytes).unwrap();
    let malformed = document
        .anomalies
        .iter()
        .find(|anomaly| {
            anomaly.kind == XmlAnomalyKind::MalformedNode(MalformedNode::AttributesOutOfBounds)
        })
        .expect("malformed node reported");
    assert!(malformed.kind.rejected_by_android());
    let root = document.root.unwrap();
    assert_eq!(root.name, "manifest");
    assert_eq!(root.elements().count(), 0);
}

#[test]
fn unknown_chunks_are_skipped_and_nesting_errors_reported() {
    let mut writer = AxmlWriter::new(&[]);
    writer.start_namespace();
    writer.start("manifest", &[]);
    writer.raw_node(0x0177, &[0; 8]);
    writer.start("application", &[]);
    writer.end("activity");
    writer.start("unclosed", &[]);
    let found = kinds(&writer.finish());
    assert!(
        found.contains(&XmlAnomalyKind::UnknownChunk { kind: 0x0177 }),
        "{found:?}"
    );
    assert!(found.contains(&XmlAnomalyKind::MismatchedEndTag {
        open: "application".into(),
        closed: "activity".into()
    }));
    assert!(found.contains(&XmlAnomalyKind::UnclosedElement {
        name: "manifest".into()
    }));
}

#[test]
fn plain_text_xml_is_not_binary_xml() {
    assert_eq!(
        xml::parse(b"<?xml version=\"1.0\"?><manifest/>").unwrap_err(),
        XmlError::NotBinaryXml
    );
    assert_eq!(xml::parse(b"").unwrap_err(), XmlError::NotBinaryXml);
}

/// Offset of the `occurrence`-th node of `kind` (0-based).
fn find_node(bytes: &[u8], kind: u16, occurrence: usize) -> usize {
    let mut position = 8;
    let mut seen = 0;
    loop {
        let chunk_kind = u16::from_le_bytes([bytes[position], bytes[position + 1]]);
        let size =
            u32::from_le_bytes(bytes[position + 4..position + 8].try_into().unwrap()) as usize;
        if chunk_kind == kind {
            if seen == occurrence {
                return position;
            }
            seen += 1;
        }
        position += size;
    }
}

fn fixture_entry(name: &str) -> Vec<u8> {
    let mut archive = ZipArchive::open(Cursor::new(BASIC_APK.to_vec()), Limits::default()).unwrap();
    archive.read_by_name(name).unwrap().unwrap()
}

/// Every single-byte mutation and every truncation of a real manifest decodes or fails
/// cleanly, and the manifest model and text rendering never panic on what decodes.
#[test]
fn manifest_mutations_never_panic() {
    let original = fixture_entry("AndroidManifest.xml");
    let exercise = |bytes: &[u8]| {
        if let Ok(document) = xml::parse(bytes) {
            let manifest = Manifest::from_document(&document);
            let _ = (manifest.min_sdk(), manifest.target_sdk(), document.to_xml());
        }
    };
    for length in 0..original.len() {
        exercise(&original[..length]);
    }
    for position in 0..original.len() {
        for replacement in [0x00, 0xff, original[position] ^ 0x80] {
            let mut mutated = original.clone();
            mutated[position] = replacement;
            exercise(&mutated);
        }
    }
}

/// Same for the resource table, with every lookup the analyses use.
#[test]
fn resource_table_mutations_never_panic() {
    let original = fixture_entry("resources.arsc");
    let exercise = |bytes: Vec<u8>| {
        if let Ok(table) = ResourceTable::parse(bytes) {
            let _ = table.locales();
            for id in [
                0x7f02_0000,
                0x7f03_0000,
                0x7f03_0001,
                0x7f04_0000,
                0x7f01_0000,
                0x0000_0001,
            ] {
                let _ = (
                    table.name(id),
                    table.values(id),
                    table.resolve(id),
                    table.files(id),
                );
            }
            let _ = table.find("string", "app_name");
            let _ = table.string(&Value::Reference(0x7f03_0000));
        }
    };
    for length in 0..original.len() {
        exercise(original[..length].to_vec());
    }
    for position in 0..original.len() {
        for replacement in [0x00, 0xff, original[position] ^ 0x80] {
            let mut mutated = original.clone();
            mutated[position] = replacement;
            exercise(mutated);
        }
    }
}

/// Found by fuzzing: start elements declaring 65,535 overlapping zero-size attributes made a
/// 64 KB document cost over a gigabyte. A document yields at most as many attributes as it has
/// room for without overlap; the rest are skipped and reported once.
#[test]
fn overlapping_attribute_declarations_stay_within_the_budget() {
    let mut writer = AxmlWriter::new(&[]);
    writer.start_namespace();
    writer.start("manifest", &[]);
    let feature = writer.string("name");
    let value = writer.string("android.hardware.camera");
    for _ in 0..5 {
        writer.start(
            "uses-feature",
            &[Attribute {
                namespace: None,
                name: feature,
                data_type: TYPE_STRING,
                data: value,
            }],
        );
        writer.end("uses-feature");
    }
    writer.end("manifest");
    let mut bytes = writer.finish();
    for occurrence in 1..=5 {
        let position = find_node(&bytes, 0x0102, occurrence);
        // attributeSize 0, attributeCount 0xffff: every attribute is the same 20 bytes.
        bytes[position + 16 + 10..position + 16 + 12].copy_from_slice(&0u16.to_le_bytes());
        bytes[position + 16 + 12..position + 16 + 14].copy_from_slice(&0xffffu16.to_le_bytes());
    }
    let document = xml::parse(&bytes).unwrap();
    let limits = document
        .anomalies
        .iter()
        .filter(|anomaly| anomaly.kind == XmlAnomalyKind::AttributeLimitReached)
        .count();
    assert_eq!(limits, 1);
    let root = document.root.unwrap();
    let decoded: usize = root
        .elements()
        .map(|element| element.attributes.len())
        .sum();
    assert_eq!(decoded, xml::attribute_budget(bytes.len()));
    assert!(
        decoded < 100,
        "{decoded} attributes from {} bytes",
        bytes.len()
    );
    assert!(!XmlAnomalyKind::AttributeLimitReached.rejected_by_android());
}
