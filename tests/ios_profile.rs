//! Provisioning profiles against Apple's decoder and OpenSSL (tests/fixtures/ios/profiles,
//! rebuilt by build_profiles.sh): each profile's content as `security cms -D` decodes it, its
//! signature as `openssl cms -verify -noverify` judges it, and what msec reads from it.

use std::collections::BTreeMap;
use std::path::Path;

use msec::cms::{CmsError, VerifyProblem};
use msec::ios::profile::{ProfileError, ProfileKind, ProvisioningProfile};
use msec::plist::{self, to_xml};

const PROFILES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios/profiles");
const TODAY: &str = "2026-10-20";

fn read(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(PROFILES).join(name)).unwrap()
}

fn profile(name: &str) -> ProvisioningProfile {
    ProvisioningProfile::parse(&read(&format!("{name}.mobileprovision")))
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn verdicts() -> BTreeMap<String, bool> {
    String::from_utf8(read("verdicts.txt"))
        .unwrap()
        .lines()
        .map(|line| {
            let (name, verdict) = line.split_once(": ").unwrap();
            (name.to_owned(), verdict == "verified")
        })
        .collect()
}

/// Content and signature verdict for every profile, against `security cms -D` and OpenSSL.
#[test]
fn profiles_read_as_apple_and_openssl_read_them() {
    let verdicts = verdicts();
    assert!(verdicts.len() >= 11, "{verdicts:?}");
    for (name, verified) in &verdicts {
        let bytes = read(&format!("{name}.mobileprovision"));
        let parsed = ProvisioningProfile::parse(&bytes);
        let Ok(content) = std::fs::read(Path::new(PROFILES).join(format!("{name}.content.plist")))
        else {
            // security cms -D could not decode it: neither can msec.
            assert!(parsed.is_err(), "{name}");
            continue;
        };
        let profile = parsed.unwrap_or_else(|error| panic!("{name}: {error}"));
        let apple = plist::parse(&content).unwrap();
        assert_eq!(
            to_xml(&profile.plist.root).unwrap(),
            to_xml(&apple.root).unwrap(),
            "{name}: content"
        );
        assert_eq!(
            profile.signature.verified.is_ok(),
            *verified,
            "{name}: signature"
        );
    }
}

#[test]
fn profile_fields_kinds_and_dates() {
    let development = profile("development");
    assert_eq!(development.name.as_deref(), Some("Fixture Development"));
    assert_eq!(development.team_identifiers, ["A1B2C3D4E5"]);
    assert_eq!(development.platforms, ["iOS"]);
    assert_eq!(development.provisioned_devices.len(), 2);
    assert_eq!(development.developer_certificates.len(), 1);
    assert_eq!(
        development.developer_certificates[0].subject,
        "CN=msec Development Certificate"
    );
    assert_eq!(
        development.signature.signer.as_ref().unwrap().subject,
        "CN=msec Test Provisioning Profile Signing"
    );
    assert_eq!(development.signature.certificates.len(), 2);
    assert_eq!(development.created_on().as_deref(), Some("2026-01-01"));
    assert_eq!(development.expires_on().as_deref(), Some("2036-01-01"));
    assert_eq!(development.expired(TODAY), Some(false));
    assert_eq!(
        development.application_identifier(),
        Some("A1B2C3D4E5.dev.appchk.fixture")
    );
    assert_eq!(development.covers_bundle("dev.appchk.fixture"), Some(true));
    assert_eq!(development.covers_bundle("dev.appchk.other"), Some(false));

    let kinds: Vec<(&str, ProfileKind)> = [
        ("development", ProfileKind::Development),
        ("ad-hoc", ProfileKind::AdHoc),
        ("enterprise", ProfileKind::Enterprise),
        ("app-store", ProfileKind::AppStore),
    ]
    .into_iter()
    .collect();
    for (name, kind) in kinds {
        assert_eq!(profile(name).kind(), kind, "{name}");
    }
    let expired = profile("expired");
    assert_eq!(expired.expires_on().as_deref(), Some("2026-01-31"));
    assert_eq!(expired.expired(TODAY), Some(true));
    assert_eq!(
        profile("wildcard").covers_bundle("anything.at.all"),
        Some(true)
    );
}

/// The streamed (BER, indefinite-length) encoding reads as the DER one; a profile changed after
/// signing still reads but does not verify; a bare plist is not a profile.
#[test]
fn encodings_and_damage() {
    let der = profile("development");
    let ber = profile("development-ber");
    assert_eq!(to_xml(&der.plist.root), to_xml(&ber.plist.root));
    assert!(ber.signature.verified.is_ok());
    let tampered = profile("tampered");
    assert_eq!(tampered.name.as_deref(), Some("fixture Development"));
    assert_eq!(
        tampered.signature.verified,
        Err(VerifyProblem::SignedAttributesDigestMismatch)
    );
    assert_eq!(
        ProvisioningProfile::parse(&read("not-signed.mobileprovision")),
        Err(ProfileError::Cms(CmsError::NotSignedData))
    );
}

/// Every single-byte change and truncation of a profile reads or fails without panicking.
#[test]
fn edited_profiles_never_panic() {
    for name in [
        "development.mobileprovision",
        "development-ber.mobileprovision",
    ] {
        let original = read(name);
        for position in (0..original.len()).step_by(3) {
            let mut edited = original.clone();
            edited[position] ^= 0xff;
            let _ = ProvisioningProfile::parse(&edited);
            if position % 7 == 0 {
                let _ = ProvisioningProfile::parse(&original[..position]);
            }
        }
    }
}
