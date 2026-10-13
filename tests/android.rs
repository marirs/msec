//! Android decoders against a real APK built by aapt2 (`tests/fixtures/android/build.sh`).
//! The binary manifest is checked line for line against `aapt2 dump xmltree` of the same file.

use std::io::Cursor;

use msec::android::manifest::{ComponentKind, InstallLocation, ManifestProblem, SdkLevel};
use msec::android::permissions::{GrantType, framework_permission};
use msec::android::xml::{self, ANDROID_NAMESPACE, XmlDocument, XmlElement};
use msec::android::{Apk, ResourceTable, Value};
use msec::archive::{Limits, ZipArchive};

const BASIC_APK: &[u8] = include_bytes!("fixtures/android/basic.apk");
const BASIC_XMLTREE: &str = include_str!("fixtures/android/basic.xmltree.txt");

fn archive(bytes: &[u8]) -> ZipArchive<Cursor<Vec<u8>>> {
    ZipArchive::open(Cursor::new(bytes.to_vec()), Limits::default()).unwrap()
}

fn entry(name: &str) -> Vec<u8> {
    archive(BASIC_APK).read_by_name(name).unwrap().unwrap()
}

/// Renders a document in the format of `aapt2 dump xmltree`.
fn aapt2_dump(document: &XmlDocument) -> String {
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
    out.push_str(&format!(
        "{}E: {} (line={})\n",
        " ".repeat(indent),
        element.name,
        element.line
    ));
    for attribute in &element.attributes {
        let name = match (&attribute.namespace, attribute.resource_id) {
            (Some(namespace), Some(id)) => format!("{namespace}:{}(0x{id:08x})", attribute.name),
            (Some(namespace), None) => format!("{namespace}:{}", attribute.name),
            (None, _) => attribute.name.clone(),
        };
        let value = match &attribute.value {
            Value::String(Some(text)) => format!("\"{text}\" (Raw: \"{text}\")"),
            other => other.to_string(),
        };
        out.push_str(&format!("{}A: {name}={value}\n", " ".repeat(indent + 2)));
    }
    for child in element.elements() {
        dump_element(out, child, indent + 4);
    }
}

#[test]
fn binary_manifest_decodes_exactly_like_aapt2() {
    let document = xml::parse(&entry("AndroidManifest.xml")).unwrap();
    assert!(document.anomalies.is_empty(), "{:?}", document.anomalies);
    let ours = aapt2_dump(&document);
    for (line_number, (ours, theirs)) in ours.lines().zip(BASIC_XMLTREE.lines()).enumerate() {
        assert_eq!(ours, theirs, "line {}", line_number + 1);
    }
    assert_eq!(ours.lines().count(), BASIC_XMLTREE.lines().count());
}

#[test]
fn manifest_model_reads_identity_and_sdk_levels() {
    let apk = Apk::read(&mut archive(BASIC_APK));
    let manifest = apk.manifest.as_ref().unwrap();
    assert_eq!(manifest.package.as_deref(), Some("com.example.fixture"));
    assert_eq!(manifest.version_code, Some(42));
    assert_eq!(apk.version_name.as_deref(), Some("1.4.2"));
    assert_eq!(apk.label.as_deref(), Some("Fixture App"));
    assert_eq!(manifest.min_sdk(), Some(24));
    assert_eq!(manifest.target_sdk(), Some(35));
    assert_eq!(manifest.compile_sdk, Some(SdkLevel::Api(37)));
    assert_eq!(manifest.platform_build_version.as_deref(), Some("17"));
    assert_eq!(manifest.install_location, Some(InstallLocation::Auto));
    assert_eq!(apk.locales, ["de", "en-GB", "ja"]);
}

#[test]
fn manifest_model_reads_permissions_features_and_screens() {
    let apk = Apk::read(&mut archive(BASIC_APK));
    let manifest = apk.manifest.unwrap();
    let names: Vec<&str> = manifest
        .uses_permissions
        .iter()
        .map(|permission| permission.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
    );
    assert_eq!(manifest.uses_permissions[2].max_sdk, Some(32));
    assert!(manifest.uses_permissions[3].never_for_location);
    assert!(manifest.uses_permissions[5].sdk_23_and_later);
    let grant = |name: &str| framework_permission(name).map(|permission| permission.grant_type());
    assert_eq!(
        grant(&manifest.uses_permissions[1].name),
        Some(GrantType::Runtime)
    );
    assert_eq!(
        grant(&manifest.uses_permissions[4].name),
        Some(GrantType::SpecialAccess)
    );

    assert_eq!(
        manifest.permissions[0].name,
        "com.example.fixture.permission.SYNC"
    );
    assert_eq!(manifest.permissions[0].protection_level, 2);
    assert_eq!(manifest.features.len(), 3);
    assert!(manifest.features[0].required);
    assert!(!manifest.features[1].required);
    assert_eq!(manifest.features[2].gl_es_version, Some(0x0003_0000));
    let screens = manifest.supports_screens.unwrap();
    assert_eq!(
        (screens.small, screens.large, screens.normal),
        (Some(false), Some(true), None)
    );
    assert_eq!(manifest.queries.packages, ["com.android.chrome"]);
    assert_eq!(manifest.queries.intents, 1);
}

#[test]
fn manifest_model_reads_the_application_and_components() {
    let apk = Apk::read(&mut archive(BASIC_APK));
    let manifest = apk.manifest.unwrap();
    let application = manifest.application.as_ref().unwrap();
    assert_eq!(
        application.name.as_deref(),
        Some("com.example.fixture.FixtureApp")
    );
    assert_eq!(
        (application.debuggable, application.allow_backup),
        (Some(true), Some(true))
    );
    assert_eq!(application.uses_cleartext_traffic, Some(false));
    assert_eq!(application.uses_libraries[0].name, "org.apache.http.legacy");
    assert!(!application.uses_libraries[0].required);
    assert_eq!(
        application.meta_data[0]
            .value
            .as_ref()
            .and_then(Value::as_str),
        Some("fixture-key")
    );

    let target = manifest.target_sdk().unwrap();
    let main = application
        .components_of(ComponentKind::Activity)
        .next()
        .unwrap();
    assert_eq!(main.name, "com.example.fixture.MainActivity");
    assert!(main.is_launcher() && main.is_exported(target));
    let links = main
        .intent_filters
        .iter()
        .find(|filter| filter.is_browsable())
        .unwrap();
    assert_eq!(links.schemes(), ["https", "fixture"]);
    assert_eq!(links.hosts(), ["example.com"]);
    assert_eq!(links.auto_verify, Some(true));

    let alias = application
        .components_of(ComponentKind::ActivityAlias)
        .next()
        .unwrap();
    assert_eq!(
        alias.target_activity.as_deref(),
        Some("com.example.fixture.MainActivity")
    );
    let receiver = application
        .components_of(ComponentKind::Receiver)
        .next()
        .unwrap();
    assert!(receiver.exported.is_none() && receiver.is_exported(target));
    let provider = application
        .components_of(ComponentKind::Provider)
        .next()
        .unwrap();
    assert_eq!(
        provider.authorities,
        ["com.example.fixture.data", "com.example.fixture.alt"]
    );
    assert_eq!(provider.grant_uri_permissions, Some(true));

    // Targeting API 35, a receiver with an intent filter must say whether it is exported.
    assert_eq!(
        manifest.problems,
        [ManifestProblem::MissingExported {
            component: "com.example.fixture.BootReceiver".into()
        }]
    );
}

#[test]
fn resource_table_resolves_names_files_and_configurations() {
    let table = ResourceTable::parse(entry("resources.arsc")).unwrap();
    assert!(table.anomalies().is_empty(), "{:?}", table.anomalies());
    assert_eq!(table.package_names(), ["com.example.fixture"]);

    let app_name = table.find("string", "app_name").unwrap();
    assert_eq!(
        table.name(app_name).unwrap().to_string(),
        "com.example.fixture:string/app_name"
    );
    let mut translations: Vec<(String, String)> = table
        .values(app_name)
        .into_iter()
        .map(|value| match value.value {
            msec::android::resources::EntryValue::Simple(Value::String(Some(text))) => {
                (value.config.qualifiers(), text)
            }
            other => panic!("{other:?}"),
        })
        .collect();
    translations.sort();
    assert_eq!(
        translations,
        [
            ("de".to_owned(), "Fixture-App".to_owned()),
            ("default".to_owned(), "Fixture App".to_owned()),
            ("en-rGB".to_owned(), "Fixture App (UK)".to_owned()),
            ("ja".to_owned(), "フィクスチャ".to_owned()),
        ]
    );

    let icon = table.find("mipmap", "ic_launcher").unwrap();
    let files = table.files(icon);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0.qualifiers(), "anydpi-v26");
    assert_eq!(files[0].1, "res/mipmap-anydpi-v26/ic_launcher.xml");
    assert_eq!(
        table.resolve(table.find("color", "icon_background").unwrap()),
        Some(Value::Color(0xff3f_e3f2))
    );
}

#[test]
fn network_security_config_is_located_and_decoded() {
    let mut archive = archive(BASIC_APK);
    let apk = Apk::read(&mut archive);
    let path = apk.network_security_config_path().unwrap();
    assert_eq!(path, "res/xml/network_security_config.xml");
    let document = xml::parse(&archive.read_by_name(&path).unwrap().unwrap()).unwrap();
    let root = document.root.as_ref().unwrap();
    assert_eq!(root.name, "network-security-config");
    let text = document.to_xml();
    assert!(
        text.contains("<base-config cleartextTrafficPermitted=\"false\"/>"),
        "{text}"
    );
    assert!(text.contains("legacy.example.com"), "{text}");
}

#[test]
fn text_rendering_uses_android_names() {
    let document = xml::parse(&entry("AndroidManifest.xml")).unwrap();
    let text = document.to_xml();
    assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest"));
    assert!(text.contains(&format!("xmlns:android=\"{ANDROID_NAMESPACE}\"")));
    assert!(
        text.contains("<uses-sdk android:minSdkVersion=\"24\" android:targetSdkVersion=\"35\"/>"),
        "{text}"
    );
    assert!(text.contains("android:label=\"@0x7f030000\""), "{text}");
}

/// The framework's own resource table (in the SDK's android.jar) names every attribute ID
/// exactly as the generated table does. Skipped when the SDK is not installed.
#[test]
fn generated_attribute_table_agrees_with_the_framework_resource_table() {
    let sdk = std::env::var("ANDROID_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join("Library/Android/sdk")
        });
    let Ok(mut android_jar) = ZipArchive::open_path(
        sdk.join("platforms/android-37.0/android.jar"),
        Limits::default(),
    ) else {
        eprintln!("Android SDK platform 37 not found; skipping");
        return;
    };
    let table =
        ResourceTable::parse(android_jar.read_by_name("resources.arsc").unwrap().unwrap()).unwrap();
    let mut compared = 0;
    for id in 0x0101_0000..0x0101_0800 {
        if let (Some(name), Some(ours)) = (table.name(id), xml::framework_attribute_name(id)) {
            assert_eq!(name.type_name, "attr");
            assert_eq!(name.entry, ours, "0x{id:08x}");
            compared += 1;
        }
    }
    assert!(compared > 1500, "only {compared} attributes compared");
    assert!(table.locales().len() > 50);
}
