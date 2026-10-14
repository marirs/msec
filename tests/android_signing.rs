//! Signature verification against APKs signed by an independent signer
//! (`tests/fixtures/android/sign_fixtures.py`: Python standard library and the openssl
//! command, no msec code).

use std::io::Cursor;

use msec::android::signing::SigningReport;
use msec::android::signing::block::BlockKind;
use msec::android::signing::crypto::{Hash, SignatureAlgorithm};
use msec::android::signing::jar::JarProblem;
use msec::android::signing::scheme::SignerProblem;
use msec::archive::{Limits, ZipArchive};

fn report(bytes: &[u8]) -> SigningReport {
    let mut archive = ZipArchive::open(Cursor::new(bytes.to_vec()), Limits::default()).unwrap();
    assert!(archive.anomalies().is_empty(), "{:?}", archive.anomalies());
    SigningReport::read(&mut archive)
}

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/android/signed/", $name, ".apk"))
    };
}

fn algorithms(
    report: &msec::android::signing::scheme::SchemeReport,
) -> Vec<Option<SignatureAlgorithm>> {
    report.signers[0]
        .algorithms
        .iter()
        .map(|algorithm| algorithm.algorithm)
        .collect()
}

#[test]
fn unsigned_apk_has_no_signature() {
    let report = report(include_bytes!("fixtures/android/basic.apk"));
    assert!(!report.is_signed());
    assert!(!report.verified());
    assert!(report.certificates().is_empty());
}

#[test]
fn v1_and_v2_with_debug_certificate_verify() {
    let report = report(fixture!("signed-v1v2-debug"));
    let v1 = report.v1.as_ref().unwrap();
    assert!(v1.verified(), "{v1:?}");
    assert_eq!(v1.signers[0].android_apk_signed, [2]);
    assert_eq!(v1.signers[0].digest, Some(Hash::Sha256));
    assert_eq!(v1.entry_digests, [Hash::Sha256]);
    let v2 = report.v2.as_ref().unwrap();
    assert!(v2.verified(), "{v2:?}");
    assert_eq!(
        algorithms(v2),
        [
            Some(SignatureAlgorithm::RsaPkcs1Sha256),
            Some(SignatureAlgorithm::RsaPssSha256)
        ]
    );
    assert!(report.verified());
    assert!(!report.schemes_stripped_from_v1());

    let certificates = report.certificates();
    assert_eq!(certificates.len(), 1, "v1 and v2 share one certificate");
    let certificate = certificates[0];
    assert!(certificate.is_debug());
    assert!(certificate.is_self_signed());
    assert_eq!(certificate.signature_algorithm, "SHA256withRSA");
    assert_eq!(certificate.hash_algorithm, Some("sha256"));
    assert_eq!(
        (
            certificate.public_key.algorithm.as_str(),
            certificate.public_key.bits
        ),
        ("RSA", Some(2048))
    );
    assert_eq!(certificate.sha256.len(), 64);
}

#[test]
fn a_changed_byte_after_signing_breaks_v2_but_not_v1() {
    let report = report(fixture!("signed-v1v2-tampered"));
    assert!(
        report.v1.as_ref().unwrap().verified(),
        "v1 does not cover the central directory"
    );
    let v2 = report.v2.as_ref().unwrap();
    assert!(!v2.verified());
    assert_eq!(
        v2.signers[0].problems,
        [
            SignerProblem::DigestMismatch(SignatureAlgorithm::RsaPkcs1Sha256),
            SignerProblem::DigestMismatch(SignatureAlgorithm::RsaPssSha256),
        ]
    );
    assert!(!report.verified());
}

#[test]
fn v2_and_v3_with_ecdsa_verify() {
    let report = report(fixture!("signed-v2v3-ec"));
    let (v2, v3) = (report.v2.as_ref().unwrap(), report.v3.as_ref().unwrap());
    assert!(v2.verified() && v3.verified(), "{v2:?} {v3:?}");
    assert!(v2.signers[0].declares_v3);
    assert_eq!(
        (v3.signers[0].min_sdk, v3.signers[0].max_sdk),
        (Some(24), Some(0x7fff_ffff))
    );
    assert!(!report.v3_stripped());
    assert!(report.v1.is_none());
    let certificate = report.certificates()[0];
    assert_eq!(
        certificate.subject,
        "CN=Example Release,O=Example Corp,C=DE"
    );
    assert_eq!(certificate.signature_algorithm, "SHA256withECDSA");
    assert_eq!(certificate.public_key.curve, Some("P-256"));
    assert!(!certificate.is_debug());
}

#[test]
fn platform_verdicts_follow_android_scheme_selection() {
    use msec::android::signing::SchemeUsed;
    let summary = |report: &SigningReport, min_sdk| {
        report
            .platform_verdicts(min_sdk, 29)
            .iter()
            .map(|verdict| (verdict.from_api, verdict.scheme, verdict.accepted()))
            .collect::<Vec<_>>()
    };
    let v1v2 = report(fixture!("signed-v1v2-debug"));
    assert_eq!(
        summary(&v1v2, 21),
        [
            (21, Some(SchemeUsed::V1), true),
            (24, Some(SchemeUsed::V2), true),
            (28, Some(SchemeUsed::V2), true),
            (30, Some(SchemeUsed::V2), true),
            (33, Some(SchemeUsed::V2), true),
        ]
    );
    // v2 is broken: Android 7.0+ rejects it even though v1 is fine; older Android accepts it.
    let tampered = report(fixture!("signed-v1v2-tampered"));
    assert_eq!(
        summary(&tampered, 21),
        [
            (21, Some(SchemeUsed::V1), true),
            (24, Some(SchemeUsed::V2), false),
            (28, Some(SchemeUsed::V2), false),
            (30, Some(SchemeUsed::V2), false),
            (33, Some(SchemeUsed::V2), false),
        ]
    );
    // No v1: Android below 7.0 has nothing to check.
    let ec = report(fixture!("signed-v2v3-ec"));
    assert_eq!(summary(&ec, 21)[0], (21, None, false));
    assert_eq!(
        summary(&ec, 28),
        [
            (28, Some(SchemeUsed::V3), true),
            (30, Some(SchemeUsed::V3), true),
            (33, Some(SchemeUsed::V3), true)
        ]
    );
    // v1 only: fine up to Android 10; Android 11+ refuse it when the app targets API 30+.
    let legacy = report(fixture!("signed-v1-legacy"));
    let accepted = |target| {
        legacy
            .platform_verdicts(24, target)
            .iter()
            .map(|verdict| verdict.accepted())
            .collect::<Vec<_>>()
    };
    assert_eq!(accepted(29), [true, true, true, true]);
    assert_eq!(accepted(30), [true, true, false, false]);
}

#[test]
fn a_stripped_v3_signature_is_detected() {
    let report = report(fixture!("signed-v3-stripped"));
    assert!(report.v2.as_ref().unwrap().verified());
    assert!(report.v3_stripped());
    // Android 7.0-8.1 accept the v2 signature; Android 9+ see the stripping and reject.
    let accepted: Vec<bool> = report
        .platform_verdicts(24, 35)
        .iter()
        .map(|verdict| verdict.accepted())
        .collect();
    assert_eq!(accepted, [true, false, false, false]);
}

#[test]
fn legacy_v1_only_signature_with_sha1_verifies() {
    let report = report(fixture!("signed-v1-legacy"));
    let v1 = report.v1.as_ref().unwrap();
    assert!(v1.verified(), "{v1:?}");
    assert_eq!(v1.signers[0].digest, Some(Hash::Sha1));
    assert_eq!(v1.entry_digests, [Hash::Sha1]);
    assert!(report.v2.is_none() && report.v3.is_none());
    let certificate = report.certificates()[0];
    assert_eq!(certificate.signature_algorithm, "SHA1withRSA");
    assert_eq!(certificate.hash_algorithm, Some("sha1"));
    assert_eq!(certificate.public_key.bits, Some(1024));
}

#[test]
fn an_entry_changed_after_v1_signing_is_reported() {
    let report = report(fixture!("signed-v1-modified-entry"));
    let v1 = report.v1.as_ref().unwrap();
    assert!(
        v1.signers[0].problems.is_empty(),
        "the signature itself is intact: {v1:?}"
    );
    assert_eq!(
        v1.problems,
        [JarProblem::EntryDigestMismatch("resources.arsc".into())]
    );
    assert!(!report.verified());
}

#[test]
fn sha512_rsa_4096_and_other_blocks() {
    let report = report(fixture!("signed-v2-rsa4096"));
    let v2 = report.v2.as_ref().unwrap();
    assert!(v2.verified(), "{v2:?}");
    assert_eq!(
        algorithms(v2),
        [
            Some(SignatureAlgorithm::RsaPkcs1Sha512),
            Some(SignatureAlgorithm::RsaPssSha512)
        ]
    );
    assert_eq!(
        report.other_blocks,
        [BlockKind::PlayFrosting, BlockKind::DependencyInfo]
    );
    let certificate = report.certificates()[0];
    assert_eq!(certificate.signature_algorithm, "SHA512withRSA");
    assert_eq!(certificate.public_key.bits, Some(4096));
}

#[test]
fn dsa_signatures_verify() {
    let report = report(fixture!("signed-v2-dsa"));
    let v2 = report.v2.as_ref().unwrap();
    assert!(v2.verified(), "{v2:?}");
    let certificate = report.certificates()[0];
    assert_eq!(
        (
            certificate.public_key.algorithm.as_str(),
            certificate.public_key.bits
        ),
        ("DSA", Some(2048))
    );
    assert_eq!(certificate.signature_algorithm, "SHA256withDSA");
}

/// Every single-byte change to a signed APK either stops it from opening, makes verification
/// fail, or leaves some Android release (from the app's minimum, API 24) unable to verify it
/// (for example a renamed v2 block: v3 still verifies, but Android 7.0-8.1 cannot use it). The
/// whole tail (signing block, central directory, end record) and every 37th byte before it.
#[test]
fn any_changed_byte_fails_verification() {
    let original = fixture!("signed-v2v3-ec").to_vec();
    assert!(report(&original).verified());
    let tail = original.len().saturating_sub(2600);
    let positions = (0..tail).step_by(37).chain(tail..original.len());
    for position in positions {
        let mut mutated = original.clone();
        mutated[position] ^= 0x41;
        if let Ok(mut archive) = ZipArchive::open(Cursor::new(mutated), Limits::default()) {
            let report = SigningReport::read(&mut archive);
            let every_release_accepts = report
                .platform_verdicts(24, 35)
                .iter()
                .all(|verdict| verdict.accepted());
            assert!(
                !(report.verified() && every_release_accepts),
                "byte {position} changed but the APK still verifies"
            );
        }
    }
}

/// `(key, detail)` of the signing findings for a fixture (manifest: minSdk 24, targetSdk 35).
fn findings(bytes: &[u8]) -> Vec<(&'static str, String)> {
    let mut archive = ZipArchive::open(Cursor::new(bytes.to_vec()), Limits::default()).unwrap();
    let apk = msec::android::Apk::read(&mut archive);
    apk.signing_findings("2026-10-14")
        .into_iter()
        .map(|finding| (finding.rule.key(), finding.detail.unwrap_or_default()))
        .collect()
}

fn rows(rows: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    rows.iter()
        .map(|(key, detail)| (*key, (*detail).to_owned()))
        .collect()
}

#[test]
fn signing_findings_per_fixture() {
    assert_eq!(
        findings(include_bytes!("fixtures/android/basic.apk")),
        rows(&[("missing_signature", "")])
    );
    assert_eq!(
        findings(fixture!("signed-v1v2-debug")),
        rows(&[
            ("signed_application", "v1, v2"),
            ("debug_certificate", "CN=Android Debug,O=Android,C=US")
        ])
    );
    assert_eq!(
        findings(fixture!("signed-v1v2-tampered")),
        rows(&[
            ("signed_application", "v1, v2"),
            ("msec_signature_invalid", "v2"),
            ("debug_certificate", "CN=Android Debug,O=Android,C=US"),
        ])
    );
    assert_eq!(
        findings(fixture!("signed-v1-legacy")),
        rows(&[
            ("signed_application", "v1"),
            ("janus_vulnerability", "minSdkVersion 24"),
            ("certificate_sha1", "SHA1withRSA"),
            ("msec_weak_signing_key", "RSA 1024-bit"),
            ("msec_v1_only_targeting_android_11", "35"),
        ])
    );
    assert_eq!(
        findings(fixture!("signed-v3-stripped")),
        rows(&[
            ("signed_application", "v2"),
            ("msec_signature_rejected_on_some_releases", "API 28+")
        ])
    );
    assert_eq!(
        findings(fixture!("signed-v2v3-ec")),
        rows(&[("signed_application", "v2, v3")])
    );
}

/// Inputs fuzzing found crashing (`fuzz/`), kept as regressions: a `META-INF/` entry name whose
/// last three bytes split a multibyte character.
#[test]
fn fuzz_regressions_read_without_panicking() {
    let jar_name = include_bytes!("fixtures/fuzz/apk-jar-name-char-boundary.bin");
    if let Ok(mut archive) = ZipArchive::open(Cursor::new(jar_name.to_vec()), Limits::default()) {
        let _ = SigningReport::read(&mut archive);
    }
}
