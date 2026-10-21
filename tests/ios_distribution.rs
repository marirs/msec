//! The distribution method on msec's distribution fixtures (tests/fixtures/ios/
//! build_distribution.sh): believed only from a profile its trusted issuer signed. The method
//! is what Apple's fields give (as `security cms -D` reads them), and the trust is what
//! OpenSSL says of the signature and of the signer's chain to the trusted root
//! (distribution-verdicts.txt). Tests trust the test root with Apple's profile-signing
//! extension (`ProfileTrust` with the test root's fingerprint); as msec runs on real apps,
//! only Apple's roots are trusted, so no test profile establishes a method there.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{
    AppRule, BinaryRule, analyse_app, analyse_binaries, certificate_distribution_mismatch,
};
use msec::ios::coverage::{UncheckedCause, UncheckedCheck, unchecked};
use msec::ios::distribution::{self, Distribution};
use msec::ios::profile::{
    APPLE_PROFILE_SIGNING_EXTENSION, ProfileKind, ProfileTrust, ProfileTrustProblem,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

const VARIANTS: [&str; 8] = [
    "development",
    "ad-hoc",
    "enterprise",
    "app-store",
    "tampered-profile",
    "developer-signed",
    "self-signed",
    "no-profile",
];

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

/// The test root as a trusted issuer, with Apple's profile-signing extension.
fn test_trust() -> ProfileTrust<'static> {
    let root = std::fs::read(Path::new(FIXTURES).join("profiles/root.der")).unwrap();
    let fingerprint = msec::android::signing::certificate::CertificateInfo::from_der(&root)
        .unwrap()
        .sha256;
    let roots: &'static [&'static str] =
        Box::leak(Box::new([&*Box::leak(fingerprint.into_boxed_str())]));
    ProfileTrust {
        roots,
        signer_extension: APPLE_PROFILE_SIGNING_EXTENSION,
    }
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

/// The method a profile the test root's profile signer issued states, by Apple's documented
/// fields: `ProvisionsAllDevices` is in-house, `get-task-allow` development, listed devices ad
/// hoc, none of these the App Store. `None` without such a profile.
fn method_of(fields: &BTreeMap<String, String>) -> Option<ProfileKind> {
    let trusted = fields["profile"] == "present"
        && fields["signature"] == "verifies"
        && fields["chain"] == "to the test root"
        && fields["profile-signing extension"] == "yes";
    if !trusted {
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
fn the_method_comes_only_from_a_profile_its_trusted_issuer_signed() {
    let readings = oracle();
    assert_eq!(
        readings
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .len(),
        VARIANTS.len()
    );
    let trust = test_trust();
    for (variant, fields) in &readings {
        let ipa = read_ipa(&format!("distribution-{variant}.ipa"));
        let app = ipa.app.as_ref().unwrap();
        let method = distribution::of_trusting(app, &trust);
        assert_eq!(method.kind(), method_of(fields), "{variant}: {method:?}");
        // As msec judges real apps, only Apple is trusted: no test profile establishes a
        // method, whatever it states.
        let as_analysed = distribution::of(app);
        assert_eq!(as_analysed.kind(), None, "{variant}");
        if let Distribution::Unknown {
            reason,
            profile_present,
        } = &as_analysed
        {
            assert_eq!(
                *profile_present,
                fields["profile"] == "present",
                "{variant}"
            );
            if *profile_present {
                assert!(reason.contains("not Apple's"), "{variant}: {reason}");
            }
        }
        // Every variant sets get-task-allow, as codesign reads it; msec reports it, and as
        // analysed the method is not established.
        assert_eq!(fields["get-task-allow"], "true", "{variant}");
        let finding = analyse_binaries(app)
            .into_iter()
            .find(|finding| finding.rule == BinaryRule::GetTaskAllow)
            .unwrap_or_else(|| panic!("{variant}"));
        assert!(
            finding.detail.contains("is not established"),
            "{variant}: {}",
            finding.detail
        );
    }
}

/// Each forgery is refused for what it lacks: a signature that verifies, a chain to the
/// trusted root, the profile-signing extension.
#[test]
fn forged_profiles_are_refused_for_what_they_lack() {
    let trust = test_trust();
    let problem = |variant: &str, trust: &ProfileTrust<'_>| {
        let ipa = read_ipa(&format!("distribution-{variant}.ipa"));
        let app = ipa.app.unwrap();
        let profile = app.profile.unwrap().unwrap();
        profile.signature.trusted(trust)
    };
    assert_eq!(problem("development", &trust), Ok(()));
    assert!(matches!(
        problem("tampered-profile", &trust),
        Err(ProfileTrustProblem::NotVerified(_))
    ));
    assert!(matches!(
        problem("developer-signed", &trust),
        Err(ProfileTrustProblem::NotProfileSigner { signer }) if signer == "msec Test Developer Certificate"
    ));
    assert!(matches!(
        problem("self-signed", &trust),
        Err(ProfileTrustProblem::NotAnchored { ending }) if ending == "msec Self-Signed Profile Signing"
    ));
    // Apple's roots do not include the test root.
    assert!(matches!(
        problem("development", &ProfileTrust::APPLE),
        Err(ProfileTrustProblem::NotAnchored { ending }) if ending == "msec Test Root CA"
    ));
}

/// get-task-allow without an Apple-established method is unchecked, forged profiles included.
#[test]
fn get_task_allow_is_unchecked_without_an_apple_profile() {
    for variant in VARIANTS {
        let ipa = read_ipa(&format!("distribution-{variant}.ipa"));
        let parts: Vec<(UncheckedCheck, UncheckedCause)> = unchecked(ipa.app.as_ref().unwrap())
            .into_iter()
            .map(|part| (part.check, part.cause))
            .collect();
        // These builds are signed ad hoc: no certificate to compare with the method.
        assert_eq!(
            parts,
            [(
                UncheckedCheck::DebuggableBuild,
                UncheckedCause::DistributionUnknown
            )],
            "{variant}"
        );
    }
    // An app that does not set get-task-allow needs no method for it.
    let store = read_ipa("store.ipa");
    assert!(
        unchecked(store.app.as_ref().unwrap())
            .iter()
            .all(|part| part.cause != UncheckedCause::DistributionUnknown)
    );
}

/// The certificate is judged against an established method only; as analysed, a profile that
/// is not Apple's leaves the check unchecked instead of passing or failing it.
#[test]
fn the_certificate_is_judged_against_an_established_method_only() {
    let ipa = read_ipa("certificate-development-app-store.ipa");
    let app = ipa.app.as_ref().unwrap();
    let path = app.provisioning_profile.clone().unwrap();
    let established = |kind| Distribution::Established {
        kind,
        profile: path.clone(),
    };
    assert!(certificate_distribution_mismatch(app, &established(ProfileKind::AppStore)).is_some());
    assert!(
        certificate_distribution_mismatch(app, &established(ProfileKind::Development)).is_none()
    );
    assert!(certificate_distribution_mismatch(app, &distribution::of(app)).is_none());
    assert!(
        !analyse_app(app, "2026-10-21")
            .iter()
            .any(|finding| finding.rule == AppRule::CertificateDistributionMismatch)
    );
    let parts: Vec<UncheckedCheck> = unchecked(app).into_iter().map(|part| part.check).collect();
    assert_eq!(parts, [UncheckedCheck::CertificateDistribution]);
}

/// Opt-in: every profile in a directory of real ones (MSEC_REAL_PROFILES, for example Xcode's
/// ~/Library/Developer/Xcode/UserData/Provisioning Profiles) is Apple's. Such profiles carry
/// a team's and its devices' identifiers and are never committed.
#[test]
fn real_profiles_are_apples() {
    let Some(directory) = std::env::var_os("MSEC_REAL_PROFILES") else {
        return;
    };
    let mut read = 0;
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path
            .extension()
            .is_none_or(|extension| extension != "mobileprovision")
        {
            continue;
        }
        let profile =
            msec::ios::profile::ProvisioningProfile::parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            profile.signature.trusted(&ProfileTrust::APPLE),
            Ok(()),
            "{}",
            path.display()
        );
        read += 1;
    }
    assert!(read > 0);
}
