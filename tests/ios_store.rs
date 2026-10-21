//! App Store requirements on the store fixture (tests/fixtures/ios/build_store.sh): the
//! protected resources each executable uses are those its imports, selectors and entitlements
//! show as Apple's tools read them (store-verdicts.txt); a resource without a usable purpose
//! string in the right bundle's Info.plist is reported; declared tracking without App Tracking
//! Transparency is reported; the SDK and minimum iOS version are held to App Store Connect's
//! upload requirements on the scan's day.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{AppRule, analyse_app};
use msec::ios::purpose_strings::{REQUIREMENTS, Signal, entitlement_uses};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

/// store-verdicts.txt: per executable, `import <symbol>`, `selector <name>` and
/// `entitlement <key>` lines.
fn oracle() -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("store-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(binary) = line.strip_suffix(':') {
            current = binary.to_owned();
            readings.insert(current.clone(), BTreeSet::new());
        } else if let Some(seen) = line.strip_prefix("  ") {
            readings.get_mut(&current).unwrap().insert(seen.to_owned());
        }
    }
    readings
}

/// A symbol as nm names it without its underscore and class prefix.
fn plain(symbol: &str) -> String {
    symbol
        .trim_start_matches("_OBJC_CLASS_$_")
        .trim_start_matches('_')
        .to_owned()
}

/// The requirements the oracle's reading satisfies, by the same signals msec applies.
fn expected_requirements(seen: &BTreeSet<String>) -> BTreeSet<usize> {
    let has = |what: String| seen.contains(&what);
    REQUIREMENTS
        .iter()
        .enumerate()
        .filter(|(_, requirement)| {
            requirement.signals.iter().any(|signal| match signal {
                Signal::Imports(symbols) => symbols
                    .iter()
                    .all(|symbol| has(format!("import {}", plain(symbol)))),
                Signal::ClassAndSelector(class, selector) => {
                    has(format!("import {}", plain(class))) && has(format!("selector {selector}"))
                }
                Signal::Entitlement(key) => has(format!("entitlement {key}")),
            })
        })
        .map(|(index, _)| index)
        .collect()
}

#[test]
fn resources_used_are_those_apples_tools_show() {
    let ipa = read_ipa("store.ipa");
    let app = ipa.app.as_ref().unwrap();
    let readings = oracle();
    assert_eq!(readings.len(), 3);
    let mut total = 0;
    for (relative, seen) in readings {
        let binary = app
            .binaries
            .iter()
            .find(|binary| binary.path == format!("{}{relative}", app.path))
            .unwrap_or_else(|| panic!("{relative}"));
        let mut found: BTreeSet<usize> = binary
            .protected_resource_uses
            .iter()
            .map(|resource_use| resource_use.requirement)
            .collect();
        if let Some(Ok(entitlements)) = binary.entitlements() {
            let dictionary = entitlements.root.as_dictionary().unwrap();
            found.extend(
                entitlement_uses(dictionary)
                    .iter()
                    .map(|resource_use| resource_use.requirement),
            );
        }
        assert_eq!(found, expected_requirements(&seen), "{relative}");
        total += found.len();
    }
    // Camera, location, contacts, motion and health in the app; Bluetooth; speech.
    assert_eq!(total, 7);
}

fn store_findings(app: &msec::ios::AppBundle, today: &str) -> Vec<(AppRule, String, String)> {
    analyse_app(app, today)
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.rule,
                AppRule::PurposeStringMissing
                    | AppRule::TrackingWithoutAtt
                    | AppRule::UploadRequirementUnmet
                    | AppRule::UploadRequirementUpcoming
            )
        })
        .map(|finding| {
            (
                finding.rule,
                finding
                    .location
                    .trim_start_matches(app.path.as_str())
                    .to_owned(),
                finding.subject.unwrap_or_default(),
            )
        })
        .collect()
}

#[test]
fn missing_purpose_strings_tracking_and_upload_requirements_are_reported() {
    let ipa = read_ipa("store.ipa");
    let app = ipa.app.as_ref().unwrap();
    let findings = store_findings(app, "2026-10-21");
    let summary: Vec<(AppRule, &str, &str)> = findings
        .iter()
        .map(|(rule, location, subject)| (*rule, location.as_str(), subject.as_str()))
        .collect();
    assert_eq!(
        summary,
        [
            // The camera's purpose string is present: no finding.
            (
                AppRule::PurposeStringMissing,
                "Info.plist",
                "NSLocationWhenInUseUsageDescription"
            ),
            (
                AppRule::PurposeStringMissing,
                "Info.plist",
                "NSContactsUsageDescription"
            ),
            (
                AppRule::PurposeStringMissing,
                "Info.plist",
                "NSBluetoothAlwaysUsageDescription"
            ),
            (
                AppRule::PurposeStringMissing,
                "Info.plist",
                "NSMotionUsageDescription"
            ),
            (
                AppRule::PurposeStringMissing,
                "Info.plist",
                "NSHealthShareUsageDescription"
            ),
            (
                AppRule::PurposeStringMissing,
                "PlugIns/Share.appex/Info.plist",
                "NSSpeechRecognitionUsageDescription"
            ),
            (AppRule::TrackingWithoutAtt, "PrivacyInfo.xcprivacy", ""),
            (
                AppRule::UploadRequirementUnmet,
                "Info.plist",
                "DTSDKName 26.0"
            ),
            (
                AppRule::UploadRequirementUpcoming,
                "Info.plist",
                "DTSDKName 27.0"
            ),
            (
                AppRule::UploadRequirementUnmet,
                "Info.plist",
                "MinimumOSVersion 13.0"
            ),
            (
                AppRule::UploadRequirementUpcoming,
                "Info.plist",
                "MinimumOSVersion 15.0"
            ),
        ],
        "{findings:#?}"
    );
    let details: Vec<String> = analyse_app(app, "2026-10-21")
        .into_iter()
        .filter(|finding| finding.rule == AppRule::PurposeStringMissing)
        .map(|finding| finding.detail)
        .collect();
    for expected in [
        "Info.plist has no NSContactsUsageDescription; Fixture uses contacts (import \
         _OBJC_CLASS_$_CNContactStore)",
        "NSLocationWhenInUseUsageDescription is empty: a purpose string must say why the app \
         needs location while the app is in use; Fixture uses location while the app is in use \
         (import _OBJC_CLASS_$_CLLocationManager, selector requestWhenInUseAuthorization)",
        "NSMotionUsageDescription is not a string (integer): iOS has no purpose string to show; \
         Fixture uses motion and fitness data (import _OBJC_CLASS_$_CMPedometer)",
        "Info.plist has no NSHealthShareUsageDescription (or NSHealthUpdateUsageDescription); \
         Fixture uses health data (entitlement com.apple.developer.healthkit)",
        "Info.plist has no NSBluetoothAlwaysUsageDescription; Frameworks/Lib.framework/Lib uses \
         Bluetooth (import _OBJC_CLASS_$_CBCentralManager)",
    ] {
        assert!(
            details.iter().any(|detail| detail == expected),
            "{details:#?}"
        );
    }
}

/// Before Apple's requirements took effect, they are announced, not in force.
#[test]
fn upload_requirements_follow_the_scan_day() {
    let ipa = read_ipa("store.ipa");
    let app = ipa.app.as_ref().unwrap();
    let upload: Vec<AppRule> = store_findings(app, "2026-01-15")
        .into_iter()
        .map(|(rule, ..)| rule)
        .filter(|rule| {
            matches!(
                rule,
                AppRule::UploadRequirementUnmet | AppRule::UploadRequirementUpcoming
            )
        })
        .collect();
    assert_eq!(upload, [AppRule::UploadRequirementUpcoming; 4]);
}

/// The original fixture uses no protected resource and declares no tracking.
#[test]
fn the_fixture_app_needs_no_purpose_string() {
    let ipa = read_ipa("fixture.ipa");
    let app = ipa.app.as_ref().unwrap();
    let findings: Vec<_> = store_findings(app, "2026-10-21")
        .into_iter()
        .filter(|(rule, ..)| {
            matches!(
                rule,
                AppRule::PurposeStringMissing | AppRule::TrackingWithoutAtt
            )
        })
        .collect();
    assert!(findings.is_empty(), "{findings:#?}");
}

/// A bundle whose code uses protected resources but whose Info.plist was not read is
/// unchecked, not clean; Info.plist without Xcode's build keys leaves the upload requirements
/// unchecked.
#[test]
fn unread_or_unrecorded_info_is_unchecked() {
    use msec::ios::coverage::{UncheckedCause, UncheckedCheck, unchecked};
    let ipa = read_ipa("store.ipa");
    let mut app = ipa.app.clone().unwrap();
    assert!(unchecked(&app).is_empty());
    app.info = None;
    let parts: Vec<(UncheckedCheck, UncheckedCause, String)> = unchecked(&app)
        .into_iter()
        .map(|part| {
            (
                part.check,
                part.cause,
                part.location
                    .trim_start_matches(app.path.as_str())
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(
        parts,
        [(
            UncheckedCheck::PurposeStrings,
            UncheckedCause::PropertyListUnreadable,
            "Info.plist".to_owned()
        )]
    );
    assert!(
        !analyse_app(&app, "2026-10-21")
            .iter()
            .any(|finding| finding.rule == AppRule::PurposeStringMissing
                && finding.location == format!("{}Info.plist", app.path))
    );
    let privacy = read_ipa("privacy.ipa");
    let parts: Vec<_> = unchecked(privacy.app.as_ref().unwrap())
        .into_iter()
        .map(|part| (part.check, part.cause, part.detail))
        .collect();
    assert_eq!(
        parts,
        [(
            UncheckedCheck::UploadRequirements,
            UncheckedCause::NotRecorded,
            "Info.plist does not record DTSDKName, which Xcode writes: App Store Connect's upload \
             requirements were not checked"
                .to_owned()
        )]
    );
}
