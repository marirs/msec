//! The IPA reader on fixtures built with Xcode's toolchain (tests/fixtures/ios, rebuilt by
//! build_ipa.sh): the fixture app's bundle and what it declares, checked against plutil and
//! the bundle's file list, and each broken variant checked against what iOS's installer (on
//! the simulator) did with the same bundle.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::{BinaryRole, ComponentKind, Ipa, IpaProblem, SignatureKind};
use msec::macho::Hardening;
use msec::plist::{Anomaly, to_xml};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

fn fixture_file(name: &str) -> String {
    std::fs::read_to_string(Path::new(FIXTURES).join(name)).unwrap()
}

#[test]
fn the_fixture_app_is_read_in_full() {
    let ipa = read_ipa("fixture.ipa");
    assert_eq!(ipa.problems, []);
    assert!(!ipa.itunes_metadata && !ipa.swift_support && !ipa.symbols);
    let app = ipa.app.unwrap();
    assert_eq!(app.path, "Payload/Fixture.app/");
    assert_eq!(
        app.executable.as_deref(),
        Some("Payload/Fixture.app/Fixture")
    );

    // Info.plist (binary, as Xcode writes it) reads as Apple reads it.
    let plist = app.info_plist.as_ref().unwrap();
    assert_eq!(
        to_xml(&plist.root).unwrap(),
        fixture_file("fixture-Info.plist.xml")
    );
    let info = app.info.as_ref().unwrap();
    assert_eq!(info.identifier.as_deref(), Some("dev.appchk.fixture"));
    assert_eq!(info.display_name.as_deref(), Some("Fixture"));
    assert_eq!(info.short_version.as_deref(), Some("2.1"));
    assert_eq!(info.version.as_deref(), Some("42"));
    assert_eq!(info.minimum_os_version.as_deref(), Some("17.0"));
    assert_eq!(info.platform_name.as_deref(), Some("iphoneos"));
    assert_eq!(info.sdk_name.as_deref(), Some("iphoneos27.1"));
    assert_eq!(info.device_families, [1, 2]);
    assert_eq!(info.required_capabilities, ["arm64"]);
    assert_eq!(info.url_schemes, ["fixture"]);
    assert_eq!(info.queried_schemes, ["whatsapp"]);
    assert_eq!(info.background_modes, ["location"]);
    assert_eq!(
        info.usage_descriptions,
        [
            (
                "NSCameraUsageDescription".to_owned(),
                "Scans documents.".to_owned()
            ),
            (
                "NSLocationWhenInUseUsageDescription".to_owned(),
                "Finds stores nearby.".to_owned()
            ),
        ]
    );
    assert_eq!(info.uses_non_exempt_encryption, Some(false));
    assert_eq!(info.file_sharing, Some(true));
    assert_eq!(info.wrong_types, []);

    // The bundle's contents, against the file list build_ipa.sh recorded.
    let listed = fixture_file("bundle.txt")
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with('#'))
        .count();
    assert_eq!(app.file_count, listed);
    let components: Vec<(ComponentKind, &str, Option<&str>)> = app
        .components
        .iter()
        .map(|component| {
            (
                component.kind,
                component.path.as_str(),
                component.executable.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        components,
        [
            (
                ComponentKind::Framework,
                "Payload/Fixture.app/Frameworks/Lib.framework/",
                Some("Payload/Fixture.app/Frameworks/Lib.framework/Lib")
            ),
            (
                ComponentKind::Library,
                "Payload/Fixture.app/Frameworks/libextra.dylib",
                Some("Payload/Fixture.app/Frameworks/libextra.dylib")
            ),
            (
                ComponentKind::AppExtension,
                "Payload/Fixture.app/PlugIns/Share.appex/",
                Some("Payload/Fixture.app/PlugIns/Share.appex/Share")
            ),
        ]
    );
    let extension = app.components[2].info.as_ref().unwrap();
    assert_eq!(
        extension.extension_point.as_deref(),
        Some("com.apple.share-services")
    );
    let manifests: Vec<(&str, bool)> = app
        .privacy_manifests
        .iter()
        .map(|manifest| (manifest.path.as_str(), manifest.problem.is_none()))
        .collect();
    assert_eq!(
        manifests,
        [
            (
                "Payload/Fixture.app/Frameworks/Lib.framework/PrivacyInfo.xcprivacy",
                true
            ),
            ("Payload/Fixture.app/PrivacyInfo.xcprivacy", true),
        ]
    );
    assert_eq!(
        app.code_resources.as_deref(),
        Some("Payload/Fixture.app/_CodeSignature/CodeResources")
    );
    assert_eq!(app.provisioning_profile, None);
    assert!(!app.fairplay_metadata);
    assert_eq!(app.localizations, ["en"]);
}

/// iOS's installer verdict per variant: `None` when it installed the bundle.
fn install_verdicts() -> BTreeMap<String, Option<String>> {
    fixture_file("install-verdicts.txt")
        .lines()
        .map(|line| {
            let (variant, verdict) = line.split_once(": ").unwrap();
            let refused = verdict.strip_prefix("refused: ").map(str::to_owned);
            (variant.to_owned(), refused)
        })
        .collect()
}

/// Every variant iOS refused has a problem msec says iOS refuses, and no variant iOS installed
/// has one; each variant's problems are the expected ones.
#[test]
fn variants_match_the_installer() {
    let expected: BTreeMap<&str, Vec<&str>> = BTreeMap::from([
        ("fixture", vec![]),
        ("no-info-plist", vec!["InfoPlistMissing"]),
        ("info-plist-truncated", vec!["InfoPlistInvalid"]),
        ("info-plist-array", vec!["InfoPlistNotDictionary"]),
        ("executable-not-declared", vec!["ExecutableNotDeclared"]),
        ("executable-missing", vec!["ExecutableMissing"]),
        ("executable-traversal", vec!["ExecutableNameInvalid"]),
        ("identifier-integer", vec!["IdentifierMissing"]),
        ("duplicate-identifier-xml", vec!["InfoPlistDuplicateKeys"]),
        (
            "duplicate-identifier-binary",
            vec!["InfoPlistDuplicateKeys"],
        ),
        // Changed after signing: layout and Info.plist are fine; the signature is not (below).
        ("info-plist-after-signing", vec![]),
        ("executable-after-signing", vec![]),
    ]);
    let verdicts = install_verdicts();
    assert_eq!(
        verdicts.keys().map(String::as_str).collect::<Vec<_>>(),
        expected.keys().copied().collect::<Vec<_>>()
    );
    for (variant, refused) in &verdicts {
        let ipa = read_ipa(&format!("{variant}.ipa"));
        let kinds: Vec<String> = ipa
            .problems
            .iter()
            .map(|problem| {
                format!("{problem:?}")
                    .split(['(', ' '])
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(kinds, expected[variant.as_str()], "{variant}");
        let msec_refuses = ipa.problems.iter().any(IpaProblem::rejected_by_ios);
        // The binary duplicate is refused for disagreeing readers inside iOS, which msec
        // reports as duplicate keys (not a refusal it can predict in general).
        if variant == "duplicate-identifier-binary" {
            assert_eq!(refused.as_deref(), Some("Mismatched bundle IDs."));
            continue;
        }
        assert_eq!(msec_refuses, refused.is_some(), "{variant}: {refused:?}");
    }
}

/// Which duplicate wins: Core Foundation keeps the last value in XML (and the installer
/// registered that identifier) and the first in a binary plist.
#[test]
fn duplicate_keys_resolve_as_ios_resolves_them() {
    let identifier = |name: &str| {
        let app = read_ipa(name).app.unwrap();
        let anomalies = app.info_plist.as_ref().unwrap().anomalies.clone();
        (app.info.unwrap().identifier.unwrap(), anomalies)
    };
    let duplicate = vec![Anomaly::DuplicateKey {
        path: "/".into(),
        key: "CFBundleIdentifier".into(),
    }];
    assert_eq!(
        identifier("duplicate-identifier-xml.ipa"),
        ("dev.appchk.fixture".to_owned(), duplicate.clone())
    );
    assert_eq!(
        install_verdicts()["duplicate-identifier-xml"],
        None,
        "installed"
    );
    assert!(
        fixture_file("install-verdicts.txt")
            .contains("duplicate-identifier-xml: installed as dev.appchk.fixture")
    );
    assert_eq!(
        identifier("duplicate-identifier-binary.ipa"),
        ("dev.appchk.first".to_owned(), duplicate)
    );
}

#[test]
fn archive_layouts_are_reported() {
    let two = read_ipa("layout-two-apps.ipa");
    assert_eq!(
        two.problems,
        [IpaProblem::MultipleAppBundles(vec![
            "Payload/Fixture.app/".into(),
            "Payload/Other.app/".into()
        ])]
    );
    assert_eq!(two.app.unwrap().path, "Payload/Fixture.app/");
    let outside = read_ipa("layout-not-in-payload.ipa");
    assert_eq!(
        outside.problems,
        [IpaProblem::AppBundleNotAtPayloadRoot("Fixture.app/".into())]
    );
    assert!(outside.app.unwrap().info.is_some());
    for name in ["layout-no-app.ipa", "layout-empty.ipa"] {
        let ipa = read_ipa(name);
        assert_eq!(ipa.problems, [IpaProblem::NoAppBundle], "{name}");
        assert!(ipa.app.is_none());
    }
}

/// Every executable of the fixture is read as Mach-O and its ad-hoc signature verifies: pages,
/// entitlements and requirements, and the bundle's Info.plist and CodeResources seals.
#[test]
fn the_fixture_executables_are_signed_and_hardened() {
    let app = read_ipa("fixture.ipa").app.unwrap();
    let roles: Vec<(BinaryRole, &str)> = app
        .binaries
        .iter()
        .map(|binary| (binary.role, binary.path.as_str()))
        .collect();
    assert_eq!(
        roles,
        [
            (BinaryRole::MainExecutable, "Payload/Fixture.app/Fixture"),
            (
                BinaryRole::Component(ComponentKind::Framework),
                "Payload/Fixture.app/Frameworks/Lib.framework/Lib"
            ),
            (
                BinaryRole::Component(ComponentKind::Library),
                "Payload/Fixture.app/Frameworks/libextra.dylib"
            ),
            (
                BinaryRole::Component(ComponentKind::AppExtension),
                "Payload/Fixture.app/PlugIns/Share.appex/Share"
            ),
        ]
    );
    for binary in &app.binaries {
        assert_eq!(binary.signatures.len(), 1, "{}", binary.path);
        let check = &binary.signatures[0];
        assert_eq!(check.kind, SignatureKind::AdHoc, "{}", binary.path);
        assert!(check.valid(), "{}: {check:?}", binary.path);
    }
    let main = &app.binaries[0];
    let check = &main.signatures[0];
    assert_eq!(check.identifier.as_deref(), Some("dev.appchk.fixture"));
    assert_eq!(
        (check.info_plist, check.resources),
        (Some(true), Some(true))
    );
    let entitlements = main.entitlements().unwrap().as_ref().unwrap();
    assert_eq!(
        entitlements.root.get("get-task-allow"),
        Some(&msec::plist::Value::Boolean(true))
    );
    let hardening = Hardening::of(main.images().next().unwrap());
    assert!(hardening.pie == Some(true) && hardening.stack_canary && hardening.arc);
    assert_eq!(hardening.encrypted, Some(false));
}

/// What codesign --verify said about each device bundle, against msec's checks of the main
/// executable's signature: Info.plist or code changed after signing is caught either way.
#[test]
fn signature_checks_match_codesign() {
    let verdicts = fixture_file("codesign-verdicts.txt");
    let mut compared = 0;
    for line in verdicts.lines() {
        let (variant, verdict) = line.split_once(": ").unwrap();
        let ipa = read_ipa(&format!("{variant}.ipa"));
        let Some(main) = ipa
            .app
            .as_ref()
            .and_then(|app| app.binaries.first())
            .filter(|binary| binary.role == BinaryRole::MainExecutable)
        else {
            continue;
        };
        let check = &main.signatures[0];
        assert_eq!(
            check.valid(),
            verdict == "valid",
            "{variant}: codesign {verdict}, {check:?}"
        );
        compared += 1;
    }
    assert!(compared >= 6, "{compared}");
    let info = read_ipa("info-plist-after-signing.ipa").app.unwrap();
    let check = &info.binaries[0].signatures[0];
    assert_eq!((check.pages, check.info_plist), (Some(true), Some(false)));
    let code = read_ipa("executable-after-signing.ipa").app.unwrap();
    let check = &code.binaries[0].signatures[0];
    assert_eq!(check.pages, Some(false));
    assert_eq!(check.mismatched_pages, [1]);
}
