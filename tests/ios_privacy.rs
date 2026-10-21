//! Privacy manifests and required-reason APIs on the privacy fixture
//! (tests/fixtures/ios/build_privacy.sh): the APIs found in each executable are those Apple's
//! nm and otool show it references (privacy-verdicts.txt); each manifest's invalid values are
//! named; undeclared categories are reported per executable; a listed SDK without a manifest
//! is reported.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{AppRule, analyse_app};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

/// privacy-verdicts.txt: per executable, `import <symbol>` and `selector <name>` lines.
fn oracle() -> BTreeMap<String, Vec<String>> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("privacy-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = None;
    for line in text.lines() {
        if let Some(binary) = line.strip_suffix(':') {
            current = Some(binary.to_owned());
            readings.insert(binary.to_owned(), Vec::new());
        } else if let (Some(binary), Some(seen)) = (&current, line.strip_prefix("  ")) {
            readings.get_mut(binary).unwrap().push(seen.to_owned());
        }
    }
    readings
}

#[test]
fn apis_found_are_those_apples_tools_list() {
    let ipa = read_ipa("privacy.ipa");
    let app = ipa.app.as_ref().unwrap();
    let readings = oracle();
    assert_eq!(readings.len(), 3);
    for (relative, seen) in readings {
        let binary = app
            .binaries
            .iter()
            .find(|binary| binary.path == format!("{}{relative}", app.path))
            .unwrap_or_else(|| panic!("{relative}"));
        // Apple's tools name symbols without the leading underscore and classes without
        // their prefix; msec's evidence keeps the symbol as imported.
        let mut found: Vec<String> = binary
            .required_reason_apis
            .iter()
            .map(|api| {
                api.evidence
                    .replace("import _OBJC_CLASS_$_", "import ")
                    .replace("import _", "import ")
            })
            .collect();
        found.sort();
        found.dedup();
        let mut seen = seen;
        seen.sort();
        assert_eq!(found, seen, "{relative}");
    }
}

#[test]
fn manifests_and_declarations_are_checked() {
    let ipa = read_ipa("privacy.ipa");
    let app = ipa.app.as_ref().unwrap();
    let findings: Vec<(AppRule, String, Option<String>, String)> = analyse_app(app, "2026-10-21")
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.rule,
                AppRule::PrivacyManifestInvalid
                    | AppRule::PrivacyReasonInvalid
                    | AppRule::RequiredReasonUndeclared
                    | AppRule::SdkPrivacyManifestMissing
            )
        })
        .map(|finding| {
            (
                finding.rule,
                finding
                    .location
                    .trim_start_matches(app.path.as_str())
                    .to_owned(),
                finding.subject,
                finding.detail,
            )
        })
        .collect();
    let summary: Vec<(AppRule, &str, Option<&str>)> = findings
        .iter()
        .map(|(rule, location, subject, _)| (*rule, location.as_str(), subject.as_deref()))
        .collect();
    assert_eq!(
        summary,
        [
            // Manifests in archive order.
            (
                AppRule::PrivacyManifestInvalid,
                "Frameworks/Lib.framework/PrivacyInfo.xcprivacy",
                None
            ),
            (AppRule::PrivacyReasonInvalid, "PrivacyInfo.xcprivacy", None),
            (
                AppRule::PrivacyManifestInvalid,
                "PrivacyInfo.xcprivacy",
                None
            ),
            (
                AppRule::RequiredReasonUndeclared,
                "Fixture",
                Some("NSPrivacyAccessedAPICategoryDiskSpace")
            ),
            (
                AppRule::RequiredReasonUndeclared,
                "Fixture",
                Some("NSPrivacyAccessedAPICategoryActiveKeyboards")
            ),
            (
                AppRule::RequiredReasonUndeclared,
                "Frameworks/Lib.framework/Lib",
                Some("NSPrivacyAccessedAPICategoryFileTimestamp")
            ),
            (
                AppRule::SdkPrivacyManifestMissing,
                "Frameworks/Alamofire.framework/",
                Some("Alamofire")
            ),
        ],
        "{findings:#?}"
    );
    let details: Vec<&str> = findings
        .iter()
        .map(|(.., detail)| detail.as_str())
        .collect();
    assert!(details.contains(
        &"ZZZZ.9 is not an approved reason for NSPrivacyAccessedAPICategorySystemBootTime"
    ));
    assert!(details.contains(
        &"\"NSPrivacyCollectedDataTypeNotAType\" is not a collected data type Apple defines"
    ));
    assert!(details.contains(&"NSPrivacyAccessedAPITypes is empty"));
}

/// The original fixture's manifests are valid and declare what its code uses.
#[test]
fn the_fixture_app_declares_what_it_uses() {
    let ipa = read_ipa("fixture.ipa");
    let app = ipa.app.as_ref().unwrap();
    let privacy: Vec<_> = analyse_app(app, "2026-10-21")
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.rule,
                AppRule::PrivacyManifestInvalid
                    | AppRule::PrivacyReasonInvalid
                    | AppRule::RequiredReasonUndeclared
                    | AppRule::SdkPrivacyManifestMissing
            )
        })
        .collect();
    assert!(privacy.is_empty(), "{privacy:#?}");
}
