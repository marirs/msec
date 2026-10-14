//! Android App Bundles and aapt2's protobuf XML. Fixtures come from `aapt2 link --proto-format`
//! (`tests/fixtures/android/build_bundle.sh`): every protobuf manifest is checked line for line
//! against `aapt2 dump xmltree` of the same file, and the APK fixtures' manifests, linked in both
//! formats, must give the same manifest model.

use std::io::{Cursor, Write};

use msec::android::bundle::{BundleProblem, Delivery, ModuleKind, RESOURCES_NOT_READ};
use msec::android::xml::{
    self, XmlAnomalyKind, XmlDocument, XmlElement, XmlError, XmlFormat, XmlNode,
};
use msec::android::{Apk, Bundle, Manifest, Value};
use msec::archive::{Limits, ZipArchive};

const BUNDLE: &[u8] = include_bytes!("fixtures/android/bundle.aab");
const BUNDLE_BASE: &[u8] = include_bytes!("fixtures/android/bundle-base.aab");

fn archive(bytes: &[u8]) -> ZipArchive<Cursor<Vec<u8>>> {
    ZipArchive::open(Cursor::new(bytes.to_vec()), Limits::default()).unwrap()
}

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/android/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn fixture_text(path: &str) -> String {
    String::from_utf8(fixture(path)).unwrap()
}

/// Renders a protobuf XML document in the format of `aapt2 dump xmltree`: namespaces nest,
/// every attribute shows its raw text, whitespace between elements shows as text nodes, and
/// references show by name (the raw text, which is how the source wrote them).
fn aapt2_proto_dump(document: &XmlDocument) -> String {
    let mut out = String::new();
    let mut indent = 0;
    for namespace in &document.namespaces {
        let prefix = namespace.prefix.as_deref().unwrap_or("");
        out.push_str(&format!(
            "{}N: {prefix}={} (line={})\n",
            " ".repeat(indent),
            namespace.uri,
            namespace.line
        ));
        indent += 2;
    }
    if let Some(root) = &document.root {
        dump_element(&mut out, root, indent);
    }
    out
}

fn dump_element(out: &mut String, element: &XmlElement, indent: usize) {
    let name = match &element.namespace {
        Some(namespace) => format!("{namespace}:{}", element.name),
        None => element.name.clone(),
    };
    out.push_str(&format!(
        "{}E: {name} (line={})\n",
        " ".repeat(indent),
        element.line
    ));
    for attribute in &element.attributes {
        let mut name = match &attribute.namespace {
            Some(namespace) => format!("{namespace}:{}", attribute.name),
            None => attribute.name.clone(),
        };
        if let Some(id) = attribute.resource_id {
            name.push_str(&format!("(0x{id:08x})"));
        }
        let raw = attribute.raw.as_deref().unwrap_or("");
        let value = match &attribute.value {
            Value::String(Some(text)) => format!("\"{text}\""),
            Value::Reference(_) | Value::Attribute(_) => raw.to_owned(),
            other => other.to_string(),
        };
        let raw = if raw.is_empty() {
            String::new()
        } else {
            format!(" (Raw: \"{raw}\")")
        };
        out.push_str(&format!(
            "{}A: {name}={value}{raw}\n",
            " ".repeat(indent + 2)
        ));
    }
    for child in &element.children {
        match child {
            XmlNode::Element(child) => dump_element(out, child, indent + 4),
            XmlNode::Text(text) => out.push_str(&format!(
                "{}T: '{}'\n",
                " ".repeat(indent + 4),
                text.replace('\n', "\\n")
            )),
        }
    }
}

fn assert_matches_dump(document: &XmlDocument, dump: &str, name: &str) {
    let ours = aapt2_proto_dump(document);
    for (line_number, (ours, theirs)) in ours.lines().zip(dump.lines()).enumerate() {
        assert_eq!(ours, theirs, "{name}: line {}", line_number + 1);
    }
    assert_eq!(ours.lines().count(), dump.lines().count(), "{name}");
}

#[test]
fn protobuf_manifests_decode_exactly_like_aapt2() {
    for name in ["basic", "risky", "network", "store", "code"] {
        let bytes = fixture(&format!("proto/{name}.AndroidManifest.pb"));
        assert_eq!(XmlFormat::detect(&bytes), Some(XmlFormat::Protobuf));
        let document = xml::parse_proto(&bytes).unwrap();
        assert!(
            document.anomalies.is_empty(),
            "{name}: {:?}",
            document.anomalies
        );
        assert_matches_dump(
            &document,
            &fixture_text(&format!("proto/{name}.xmltree.txt")),
            name,
        );
    }
    let mut bundle = archive(BUNDLE);
    for module in ["base", "camera", "textures"] {
        let bytes = bundle
            .read_by_name(&format!("{module}/manifest/AndroidManifest.xml"))
            .unwrap()
            .unwrap();
        let document = xml::parse_proto(&bytes).unwrap();
        assert_matches_dump(
            &document,
            &fixture_text(&format!("bundle/{module}.xmltree.txt")),
            module,
        );
    }
}

/// The same source manifest compiled to binary XML (in the APK fixture) and to protobuf XML
/// (as in a bundle) gives the same manifest model, so every manifest check reads both alike.
#[test]
fn protobuf_and_binary_manifests_model_the_same_app() {
    for name in ["basic", "risky", "network", "store", "code"] {
        let apk = fixture(&format!("{name}.apk"));
        let binary = archive(&apk)
            .read_by_name("AndroidManifest.xml")
            .unwrap()
            .unwrap();
        assert_eq!(XmlFormat::detect(&binary), Some(XmlFormat::Binary));
        let from_binary = Manifest::from_document(&xml::parse(&binary).unwrap());
        let protobuf = fixture(&format!("proto/{name}.AndroidManifest.pb"));
        let from_protobuf = Manifest::from_document(&xml::parse_proto(&protobuf).unwrap());
        assert_eq!(from_binary, from_protobuf, "{name}");
        // Android cannot read the protobuf format; the binary reader says which it is.
        assert_eq!(xml::parse(&protobuf), Err(XmlError::ProtobufNotBinary));
    }
}

#[test]
fn a_bundle_lists_its_modules_and_their_delivery() {
    let bundle = Bundle::read(&mut archive(BUNDLE));
    assert!(bundle.problems.is_empty(), "{:?}", bundle.problems);
    let names: Vec<&str> = bundle
        .modules
        .iter()
        .map(|module| module.name.as_str())
        .collect();
    assert_eq!(names, ["base", "camera", "textures"]);
    let base = &bundle.modules[0];
    assert_eq!(base.info.kind, ModuleKind::Base);
    assert_eq!(base.manifest_format, Some(XmlFormat::Protobuf));
    assert_eq!(base.contents.dex_files, 1);
    assert_eq!(base.contents.native_libraries, 1);
    assert_eq!(base.contents.abis, ["arm64-v8a"]);
    assert!(base.contents.resource_table);

    let camera = &bundle.modules[1];
    assert_eq!(camera.info.kind, ModuleKind::Feature);
    assert_eq!(camera.info.delivery, Delivery::OnDemand);
    assert_eq!(camera.info.fused, Some(true));
    assert_eq!(camera.info.split.as_deref(), Some("camera"));
    assert_eq!(
        camera.info.title,
        Some(Value::String(Some("Camera".into())))
    );
    let camera_manifest = camera.manifest.as_ref().unwrap();
    assert_eq!(
        camera_manifest.uses_permissions[0].name,
        "android.permission.CAMERA"
    );
    assert_eq!(
        camera_manifest
            .application
            .as_ref()
            .unwrap()
            .components
            .len(),
        1
    );

    let textures = &bundle.modules[2];
    assert_eq!(textures.info.kind, ModuleKind::AssetPack);
    assert_eq!(textures.info.delivery, Delivery::FastFollow);
    assert_eq!(textures.contents.assets, 1);

    assert_eq!(
        bundle
            .config
            .as_ref()
            .unwrap()
            .bundletool_version
            .as_deref(),
        Some("0.0.0-fixture")
    );
    // The upload key's JAR signature (jarsigner), verified.
    assert!(bundle.signing.v1.is_some() && bundle.signing.verified());
}

/// The base module as an APK: the manifest and an APK-shaped inventory; what is not read in a
/// bundle says so.
#[test]
fn the_base_module_reads_as_an_apk() {
    let bundle = Bundle::read(&mut archive(BUNDLE_BASE));
    assert_eq!(bundle.modules.len(), 1);
    let base: &Apk = bundle.base.as_ref().unwrap();
    let manifest = base.manifest.as_ref().unwrap();
    assert_eq!(
        manifest.package.as_deref(),
        Some("dev.appchk.fixture.bundle")
    );
    assert_eq!(manifest.version_code, Some(12));
    assert_eq!(manifest.target_sdk(), Some(35));
    assert_eq!(base.version_name.as_deref(), Some("3.1"));
    // @string/app_name needs resources.pb.
    assert_eq!(base.label, None);
    assert!(matches!(&base.resources, Some(Err(reason)) if reason == RESOURCES_NOT_READ));
    assert!(matches!(base.network_security_config, Some(Err(_))));
    assert_eq!(base.inventory.dex_files, ["classes.dex"]);
    assert_eq!(base.inventory.abis.len(), 1);
    assert!(base.native_libraries.is_empty() && base.dex_files.is_empty());
    // Manifest checks run on it.
    assert!(!base.manifest_findings().is_empty());
    assert!(!base.store_findings("2026-10-14").is_empty());
}

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        writer
            .start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn structural_problems_are_reported() {
    let binary_manifest = archive(&fixture("basic.apk"))
        .read_by_name("AndroidManifest.xml")
        .unwrap()
        .unwrap();
    let camera = archive(BUNDLE)
        .read_by_name("camera/manifest/AndroidManifest.xml")
        .unwrap()
        .unwrap();
    // A binary (APK) manifest in the base module: flagged, and still read.
    let bundle = Bundle::read(&mut archive(&zip(&[
        ("base/manifest/AndroidManifest.xml", &binary_manifest),
        ("stray/notes.txt", b"not a module"),
        // The camera manifest says split="camera"; this directory is named otherwise.
        ("photos/manifest/AndroidManifest.xml", &camera),
    ])));
    assert_eq!(
        bundle.problems,
        [
            BundleProblem::DirectoryWithoutManifest("stray".into()),
            BundleProblem::BinaryManifest("base".into()),
            BundleProblem::SplitNameMismatch {
                module: "photos".into(),
                split: Some("camera".into()),
            },
            BundleProblem::NoBundleConfig,
        ]
    );
    assert_eq!(bundle.modules[0].manifest_format, Some(XmlFormat::Binary));
    assert!(bundle.base.as_ref().unwrap().manifest.is_some());

    // No base module: no app to describe.
    let bundle = Bundle::read(&mut archive(&zip(&[(
        "camera/manifest/AndroidManifest.xml",
        &camera,
    )])));
    assert!(bundle.problems.contains(&BundleProblem::NoBaseModule));
    assert!(bundle.base.is_none());
}

/// Protobuf that protobuf's own parser rejects fails the document; deep nesting is cut at the
/// depth limit instead of recursing without end.
#[test]
fn hostile_protobuf_xml_is_bounded() {
    let manifest = fixture("proto/basic.AndroidManifest.pb");
    for length in 0..manifest.len() {
        // Every prefix either decodes or fails cleanly.
        let _ = xml::parse_proto(&manifest[..length]);
    }
    assert!(matches!(
        xml::parse_proto(&manifest[..manifest.len() / 2]),
        Err(XmlError::InvalidProtobuf(_))
    ));

    // XmlNode { element { name: "e", child: XmlNode { element { ... } } } }, 400 deep.
    let mut node: Vec<u8> = Vec::new();
    for _ in 0..400 {
        let mut element = vec![0x1a, 0x01, b'e'];
        if !node.is_empty() {
            element.push(0x2a);
            push_length(&mut element, node.len());
            element.extend_from_slice(&node);
        }
        node = vec![0x0a];
        push_length(&mut node, element.len());
        node.extend_from_slice(&element);
    }
    let document = xml::parse_proto(&node).unwrap();
    assert!(
        document
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == XmlAnomalyKind::DepthLimitReached)
    );
}

fn push_length(out: &mut Vec<u8>, mut length: usize) {
    loop {
        let byte = (length & 0x7f) as u8;
        length >>= 7;
        if length == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}
