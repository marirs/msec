//! iOS store-review leads and private frameworks on msec's store-lead fixtures
//! (tests/fixtures/ios/build_store_leads.sh): the positive app gives each finding once, naming
//! what otool and nm read (leads-verdicts.txt); the clean app gives none; an App Store-encrypted
//! main executable leaves the selector and string checks unchecked, not clean.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{AppRule, BinaryEvidence, analyse_app};
use msec::ios::coverage::{UncheckedCause, UncheckedCheck, unchecked};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

const LEADS: [AppRule; 5] = [
    AppRule::PaymentSdkWithoutStoreKit,
    AppRule::ThirdPartyLoginWithoutEquivalent,
    AppRule::AccountDeletionNotSeen,
    AppRule::PrivateFrameworkLinked,
    AppRule::PrivateFrameworkPath,
];

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

/// leads-verdicts.txt: per `<variant> Fixture`, its lines.
fn oracle() -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("leads-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        // Headers are not indented; selectors in the lines below also end with ':'.
        if let Some(seen) = line.strip_prefix("  ") {
            readings.get_mut(&current).unwrap().insert(seen.to_owned());
        } else if let Some(name) = line.strip_suffix(':') {
            current = name.to_owned();
            readings.insert(current.clone(), BTreeSet::new());
        }
    }
    readings
}

/// `(rule, location within the app, subject)` of the lead findings.
fn leads(ipa: &Ipa) -> Vec<(AppRule, String, String)> {
    let app = ipa.app.as_ref().unwrap();
    let mut found: Vec<(AppRule, String, String)> = analyse_app(app, "2026-10-22")
        .into_iter()
        .filter(|finding| LEADS.contains(&finding.rule))
        .map(|finding| {
            (
                finding.rule,
                finding
                    .location
                    .strip_prefix(app.path.as_str())
                    .unwrap()
                    .to_owned(),
                finding.subject.unwrap(),
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn each_finding_is_what_otool_and_nm_read() {
    let seen = &oracle()["positive Fixture"];
    for line in [
        "library @rpath/Stripe.framework/Stripe",
        "library @rpath/GoogleSignIn.framework/GoogleSignIn",
        "library /System/Library/PrivateFrameworks/AppchkFixture.framework/AppchkFixture",
        "class GIDSignIn",
        "selector createUserWithEmail:password:completion:",
        "string /System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices",
    ] {
        assert!(seen.contains(line), "{line}");
    }
    assert!(!seen.iter().any(|line| line.contains("StoreKit")
        || line.contains("ASAuthorization")
        || line.contains("deleteWithCompletion:")));
    let mut expected = vec![
        (
            AppRule::PaymentSdkWithoutStoreKit,
            "Info.plist".to_owned(),
            "Stripe".to_owned(),
        ),
        (
            AppRule::ThirdPartyLoginWithoutEquivalent,
            "Info.plist".to_owned(),
            "GoogleSignIn".to_owned(),
        ),
        (
            AppRule::AccountDeletionNotSeen,
            "Fixture".to_owned(),
            "createUserWithEmail:password:completion:".to_owned(),
        ),
        (
            AppRule::PrivateFrameworkLinked,
            "Fixture".to_owned(),
            "/System/Library/PrivateFrameworks/AppchkFixture.framework/AppchkFixture".to_owned(),
        ),
        (
            AppRule::PrivateFrameworkPath,
            "Fixture".to_owned(),
            "/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices"
                .to_owned(),
        ),
    ];
    expected.sort();
    assert_eq!(leads(&read_ipa("leads.ipa")), expected);
    assert_eq!(
        AppRule::AccountDeletionNotSeen.evidence(),
        Some(BinaryEvidence::String)
    );
    assert_eq!(
        AppRule::PrivateFrameworkLinked.evidence(),
        Some(BinaryEvidence::Import)
    );
    assert_eq!(AppRule::AtsArbitraryLoads.evidence(), None);
}

#[test]
fn the_clean_app_gives_none() {
    let seen = &oracle()["clean Fixture"];
    assert!(seen.contains("library /System/Library/Frameworks/StoreKit.framework/StoreKit"));
    assert!(seen.contains("class ASAuthorizationAppleIDProvider"));
    assert!(seen.contains("selector deleteWithCompletion:"));
    assert_eq!(leads(&read_ipa("leads-clean.ipa")), []);
}

/// Encrypted, the clean app's selectors and strings are unread: the deletion and private-path
/// checks are unchecked for it (and report nothing); load commands and imports still decide the
/// others.
#[test]
fn encrypted_selectors_and_strings_are_unchecked() {
    let ipa = read_ipa("leads-incomplete.ipa");
    let app = ipa.app.as_ref().unwrap();
    assert_eq!(leads(&ipa), []);
    let parts: Vec<(UncheckedCheck, UncheckedCause)> = unchecked(app)
        .into_iter()
        .filter(|part| part.location.ends_with("Fixture.app/Fixture"))
        .map(|part| (part.check, part.cause))
        .collect();
    assert!(parts.contains(&(UncheckedCheck::MethodNames, UncheckedCause::Encrypted)));
    assert!(parts.contains(&(UncheckedCheck::Strings, UncheckedCause::Encrypted)));
    assert!(
        UncheckedCheck::MethodNames
            .keys()
            .contains(&AppRule::AccountDeletionNotSeen.key())
    );
    assert!(
        UncheckedCheck::Strings
            .keys()
            .contains(&AppRule::PrivateFrameworkPath.key())
    );
}
