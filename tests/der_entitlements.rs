//! DER entitlements (`msec::macho::der_entitlements`) against what codesign wrote: the DER
//! encoding of entitlements of every value type decodes to the XML codesign embedded beside it
//! (tests/fixtures/macho/build_der_entitlements.sh), on every fixture that carries both, and a
//! DER blob changed on its own is told apart.

use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::macho::der_entitlements::same_entitlements;
use msec::macho::parse;
use msec::macho::signature::CodeSignature;
use msec::plist::{self, Value};

const MACHO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/macho");

fn signature(bytes: &[u8]) -> CodeSignature {
    let file = parse(bytes).unwrap();
    let image = file.slices[0].image.as_ref().unwrap();
    image.signature.as_ref().unwrap().as_ref().unwrap().clone()
}

fn xml_of(signature: &CodeSignature) -> plist::Dictionary {
    let entitlements = signature.entitlements.as_ref().unwrap();
    match &entitlements.plist.as_ref().unwrap().root {
        Value::Dictionary(dictionary) => dictionary.clone(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn der_entitlements_equal_the_xml_codesign_wrote() {
    let bytes = std::fs::read(Path::new(MACHO).join("der/der-entitlements")).unwrap();
    let signature = signature(&bytes);
    let der = signature.der_entitlements_decoded().unwrap().unwrap();
    assert!(der.duplicate_keys.is_empty());
    let oracle =
        plist::parse(&std::fs::read(Path::new(MACHO).join("der/der-entitlements.xml")).unwrap())
            .unwrap();
    let Value::Dictionary(oracle) = oracle.root else {
        panic!("not a dictionary");
    };
    assert!(
        same_entitlements(&der.dictionary, &oracle),
        "{:#?}\n{oracle:#?}",
        der.dictionary
    );
    assert!(same_entitlements(&der.dictionary, &xml_of(&signature)));
    // Every value type came through.
    assert_eq!(
        der.dictionary.get("com.apple.developer.fixture.count"),
        Some(&Value::Integer(300))
    );
    assert_eq!(
        der.dictionary.get("com.apple.developer.fixture.offset"),
        Some(&Value::Integer(-2))
    );
    assert_eq!(
        der.dictionary.get("com.apple.developer.fixture.name"),
        Some(&Value::String("Fixture ünïcode ✓".to_owned()))
    );
    assert!(matches!(
        der.dictionary.get("com.apple.developer.fixture.nested"),
        Some(Value::Dictionary(_))
    ));
}

/// codesign --verify accepts the mismatch (its slot hash was updated); the encodings differ,
/// and iOS 15 and later read the DER one.
#[test]
fn a_der_blob_changed_alone_differs_from_the_xml() {
    let verdicts =
        std::fs::read_to_string(Path::new(MACHO).join("der/der-entitlements.verify.txt")).unwrap();
    assert!(verdicts.contains("der-entitlements-mismatch: valid"));
    let bytes = std::fs::read(Path::new(MACHO).join("der/der-entitlements-mismatch")).unwrap();
    let signature = signature(&bytes);
    let der = signature.der_entitlements_decoded().unwrap().unwrap();
    assert_eq!(
        der.dictionary.get("get-task-allow"),
        Some(&Value::Boolean(false))
    );
    assert_eq!(
        xml_of(&signature).get("get-task-allow"),
        Some(&Value::Boolean(true))
    );
    assert!(!same_entitlements(&der.dictionary, &xml_of(&signature)));
}

/// Every executable of every IPA fixture that carries both encodings carries the same
/// entitlements in each.
#[test]
fn ipa_fixtures_agree() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ios/ipa");
    let mut compared = 0;
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        // Built to disagree (build_rule_variants.sh): its executable is
        // macho/der/der-entitlements-mismatch, which the DER fixtures test above checks.
        if path.ends_with("variant-der-mismatch.ipa") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
        let Some(app) = msec::ios::Ipa::read(&mut archive).app else {
            continue;
        };
        for binary in &app.binaries {
            for image in binary.images() {
                let Some(Ok(signature)) = &image.signature else {
                    continue;
                };
                let (Some(Ok(der)), Some(entitlements)) = (
                    signature.der_entitlements_decoded(),
                    &signature.entitlements,
                ) else {
                    continue;
                };
                let Ok(xml) = &entitlements.plist else {
                    continue;
                };
                let Value::Dictionary(xml) = &xml.root else {
                    continue;
                };
                assert!(
                    same_entitlements(&der.dictionary, xml),
                    "{}: {}",
                    path.display(),
                    binary.path
                );
                compared += 1;
            }
        }
    }
    assert!(compared > 10, "{compared}");
}

/// The analysis names the keys the encodings disagree on, and only for the changed binary.
#[test]
fn the_analysis_reports_differing_entitlements() {
    use msec::ios::analysis::{BinaryRule, analyse_binary};
    use msec::ios::{BinaryRole, BundleBinary, Sealing};
    let findings = |name: &str| {
        let bytes = std::fs::read(Path::new(MACHO).join("der").join(name)).unwrap();
        let binary =
            BundleBinary::from_bytes(name, BinaryRole::MainExecutable, &bytes, Sealing::Itself);
        analyse_binary(&binary)
            .into_iter()
            .filter(|finding| finding.rule == BinaryRule::EntitlementsDiffer)
            .map(|finding| finding.detail)
            .collect::<Vec<_>>()
    };
    assert_eq!(findings("der-entitlements"), Vec::<String>::new());
    assert_eq!(
        findings("der-entitlements-mismatch"),
        [
            "the DER entitlements (read by iOS 15 and later) differ from the XML ones in get-task-allow"
        ]
    );
}
