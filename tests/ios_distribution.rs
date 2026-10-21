//! The distribution method on msec's distribution fixtures (tests/fixtures/ios/
//! build_distribution.sh): established from the embedded provisioning profile only when its
//! signature verifies, with the method Apple's fields give (as `security cms -D` and
//! `openssl cms -verify` read them, distribution-verdicts.txt); otherwise not established, and
//! the checks that depend on it are reported as unchecked.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{AppRule, BinaryRule, analyse_app, analyse_binaries};
use msec::ios::coverage::{UncheckedCause, UncheckedCheck, unchecked};
use msec::ios::distribution::{self, Distribution};
use msec::ios::profile::ProfileKind;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

/// distribution-verdicts.txt: per variant, `field: value` lines.
fn oracle() -> BTreeMap<String, BTreeMap<String, String>> {
    let text =
        std::fs::read_to_string(Path::new(FIXTURES).join("distribution-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(variant) = line.strip_suffix(':') {
            current = variant.to_owned();
            readings.insert(current.clone(), BTreeMap::new());
        } else if let Some((field, value)) = line.trim().split_once(": ") {
            readings
                .get_mut(&current)
                .unwrap()
                .insert(field.to_owned(), value.to_owned());
        }
    }
    readings
}

/// The method Apple's documented profile fields give: `ProvisionsAllDevices` is in-house,
/// `get-task-allow` development, listed devices ad hoc, none of these the App Store.
fn method_of(fields: &BTreeMap<String, String>) -> Option<ProfileKind> {
    if fields["profile"] == "none" || fields["signature"] != "verifies" {
        return None;
    }
    Some(if fields["ProvisionsAllDevices"] == "true" {
        ProfileKind::Enterprise
    } else if fields["profile get-task-allow"] == "true" {
        ProfileKind::Development
    } else if fields["ProvisionedDevices"] != "0" {
        ProfileKind::AdHoc
    } else {
        ProfileKind::AppStore
    })
}

#[test]
fn the_method_is_what_apples_tools_read_from_a_trusted_profile() {
    let readings = oracle();
    assert_eq!(readings.len(), 6);
    for (variant, fields) in &readings {
        let ipa = read_ipa(&format!("distribution-{variant}.ipa"));
        let app = ipa.app.as_ref().unwrap();
        let method = distribution::of(app);
        assert_eq!(method.kind(), method_of(fields), "{variant}: {method:?}");
        if let Distribution::Unknown {
            profile_present, ..
        } = &method
        {
            assert_eq!(
                *profile_present,
                fields["profile"] == "present",
                "{variant}"
            );
        }
        // Every variant sets get-task-allow, as codesign reads it, and msec reports it with
        // what the method makes of it.
        assert_eq!(fields["get-task-allow"], "true", "{variant}");
        let finding = analyse_binaries(app)
            .into_iter()
            .find(|finding| finding.rule == BinaryRule::GetTaskAllow)
            .unwrap_or_else(|| panic!("{variant}"));
        let expected = match method.kind() {
            Some(ProfileKind::Development) => "as a development build",
            Some(_) => "distribution",
            None => "is not established",
        };
        assert!(
            finding.detail.contains(expected),
            "{variant}: {}",
            finding.detail
        );
    }
}

/// get-task-allow without an established method is unchecked; with one, it is not.
#[test]
fn an_unknown_method_leaves_get_task_allow_unchecked() {
    for (variant, unknown) in [
        ("development", false),
        ("ad-hoc", false),
        ("enterprise", false),
        ("app-store", false),
        ("tampered-profile", true),
        ("no-profile", true),
    ] {
        let ipa = read_ipa(&format!("distribution-{variant}.ipa"));
        let parts: Vec<(UncheckedCheck, UncheckedCause)> = unchecked(ipa.app.as_ref().unwrap())
            .into_iter()
            .map(|part| (part.check, part.cause))
            .collect();
        let expected: &[(UncheckedCheck, UncheckedCause)] = if unknown {
            &[(
                UncheckedCheck::DebuggableBuild,
                UncheckedCause::DistributionUnknown,
            )]
        } else {
            &[]
        };
        // These builds are signed ad hoc: no certificate to compare with the method.
        assert_eq!(parts, expected, "{variant}");
    }
    // An app that does not set get-task-allow needs no method for it.
    let store = read_ipa("store.ipa");
    assert!(
        unchecked(store.app.as_ref().unwrap())
            .iter()
            .all(|part| part.cause != UncheckedCause::DistributionUnknown)
    );
}

/// The certificate is judged only against a trusted profile: one whose signature does not
/// verify leaves the check unchecked instead of passing or failing it.
#[test]
fn the_certificate_is_judged_against_a_trusted_profile_only() {
    let ipa = read_ipa("certificate-development-app-store.ipa");
    let app = ipa.app.clone().unwrap();
    let mismatch = |app: &msec::ios::AppBundle| {
        analyse_app(app, "2026-10-21")
            .iter()
            .any(|finding| finding.rule == AppRule::CertificateDistributionMismatch)
    };
    assert!(mismatch(&app));
    assert!(unchecked(&app).is_empty());
    let mut untrusted = app.clone();
    if let Some(Ok(profile)) = &mut untrusted.profile {
        profile.signature.verified = Err(msec::cms::VerifyProblem::SignatureInvalid);
    }
    assert!(!mismatch(&untrusted));
    let parts: Vec<UncheckedCheck> = unchecked(&untrusted)
        .into_iter()
        .map(|part| part.check)
        .collect();
    assert_eq!(parts, [UncheckedCheck::CertificateDistribution]);
}
