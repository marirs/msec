//! Code-signing certificates (`msec::macho::signer`) on the certificate-signed IPA fixtures
//! (tests/fixtures/ios, build_certificate_signed.sh): the CMS signature over the primary
//! CodeDirectory, the certificate chain with every link verified, what the certificate is for,
//! the team and the signing time, each compared with what Apple's codesign read from the same
//! bundles (certificate-verdicts.txt).
//!
//! The fixtures' chain is a test chain, so it is never anchored to Apple. An Apple-issued chain
//! is checked by `real_apple_signature`, which runs only when MSEC_REAL_IPA names an IPA signed
//! by Apple's certificates (an Xcode development build zipped as Payload/<App>.app) and
//! MSEC_REAL_TEAM gives the TeamIdentifier `codesign -dvvv` prints for it.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::cms::VerifyProblem;
use msec::ios::{BinaryRole, Ipa, SignatureCheck, SignatureKind};
use msec::macho::signer::{CertificateUse, SignerProblem};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

fn read_ipa(path: &Path) -> Ipa {
    let bytes = std::fs::read(path).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

fn main_signature(ipa: &Ipa) -> SignatureCheck {
    let app = ipa.app.as_ref().unwrap();
    app.binaries
        .iter()
        .find(|binary| binary.role == BinaryRole::MainExecutable)
        .unwrap()
        .signatures[0]
        .clone()
}

/// certificate-verdicts.txt: per variant, the `Authority=` names and `TeamIdentifier=`
/// codesign printed.
fn codesign_readings() -> BTreeMap<String, (Vec<String>, String)> {
    let text =
        std::fs::read_to_string(Path::new(FIXTURES).join("certificate-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, (Vec<String>, String)> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(name) = line.strip_suffix(':') {
            current = name.to_owned();
            readings.insert(current.clone(), (Vec::new(), String::new()));
        } else if let Some(authority) = line.trim().strip_prefix("Authority=") {
            readings
                .get_mut(&current)
                .unwrap()
                .0
                .push(authority.to_owned());
        } else if let Some(team) = line.trim().strip_prefix("TeamIdentifier=") {
            readings.get_mut(&current).unwrap().1 = team.to_owned();
        }
    }
    readings
}

#[test]
fn certificate_chains_match_codesign() {
    let readings = codesign_readings();
    assert_eq!(readings.len(), 7);
    for (variant, (authorities, team)) in &readings {
        let ipa = read_ipa(&Path::new(FIXTURES).join(format!("ipa/certificate-{variant}.ipa")));
        let signature = main_signature(&ipa);
        assert_eq!(signature.kind, SignatureKind::Certificate, "{variant}");
        assert_eq!(
            signature.team_id.as_deref(),
            Some(team.as_str()),
            "{variant}"
        );
        let signer = signature.signer.as_ref().unwrap();
        if variant == "cms-tampered" {
            // codesign shows no authorities for a signature that does not verify.
            assert_eq!(authorities, &["(unavailable)"]);
            assert_eq!(
                signer.signature,
                Err(SignerProblem::Verify(VerifyProblem::SignatureInvalid))
            );
            continue;
        }
        if variant == "ed25519" {
            // Neither codesign nor msec verifies an Ed25519 code signature: codesign names no
            // authority and calls it invalid; msec says it did not verify it, not that it is
            // invalid (whether iOS accepts it is not established here).
            assert_eq!(authorities, &["(unavailable)"]);
            assert!(
                signer
                    .signature
                    .as_ref()
                    .is_err_and(|problem| problem.unsupported()),
                "{:?}",
                signer.signature
            );
            continue;
        }
        assert_eq!(signer.signature, Ok(()), "{variant}");
        let chain: Vec<&str> = signer
            .chain
            .iter()
            .map(|link| link.common_name.as_deref().unwrap())
            .collect();
        assert_eq!(&chain, authorities, "{variant}");
        assert_eq!(signer.chain[0].verified_by_next, Some(true), "{variant}");
        assert_eq!(signer.chain[1].verified_by_next, Some(true), "{variant}");
        assert_eq!(
            signer.chain[2].verified_by_next, None,
            "{variant}: the root is last"
        );
        assert_eq!(signer.unlinked, 0);
        // A test root: never Apple's.
        assert!(!signer.apple_anchored, "{variant}");
        // The certificate's team is A1B2C3D4E5 in every variant; team-mismatch's CodeDirectory
        // names another (codesign --verify accepts that; iOS refuses it at install).
        assert_eq!(signer.team_id.as_deref(), Some("A1B2C3D4E5"), "{variant}");
        assert!(signer.signing_time.is_some(), "{variant}");
    }
}

#[test]
fn certificate_uses_and_the_leaf_certificate() {
    let certificate =
        |name: &str| std::fs::read(Path::new(FIXTURES).join("certificates").join(name)).unwrap();
    for (variant, expected_use, leaf) in [
        (
            "development",
            CertificateUse::Development,
            "development.der",
        ),
        (
            "distribution",
            CertificateUse::Distribution,
            "distribution.der",
        ),
    ] {
        let ipa = read_ipa(&Path::new(FIXTURES).join(format!("ipa/certificate-{variant}.ipa")));
        let signer = main_signature(&ipa).signer.unwrap();
        assert_eq!(signer.certificate_use, expected_use, "{variant}");
        assert_eq!(signer.leaf().unwrap().der, certificate(leaf), "{variant}");
        assert_eq!(signer.chain[2].certificate.der, certificate("root.der"));
    }
    // Ad hoc signatures have no signer.
    let ad_hoc = read_ipa(&Path::new(FIXTURES).join("ipa/fixture.ipa"));
    assert_eq!(main_signature(&ad_hoc).signer, None);
}

/// An IPA signed with Apple's certificates: anchored to Apple's root, the team codesign
/// reports. Opt-in (see the module documentation): such builds carry a person's name and are
/// not committed.
#[test]
fn real_apple_signature() {
    let (Some(path), Some(team)) = (
        std::env::var_os("MSEC_REAL_IPA"),
        std::env::var("MSEC_REAL_TEAM").ok(),
    ) else {
        return;
    };
    let ipa = read_ipa(Path::new(&path));
    // No signer finding on any executable of a bundle Apple's chain signed.
    let signer_findings: Vec<_> = msec::ios::analysis::analyse_binaries(ipa.app.as_ref().unwrap())
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.rule,
                msec::ios::analysis::BinaryRule::CmsSignatureInvalid
                    | msec::ios::analysis::BinaryRule::SignerNotApple
                    | msec::ios::analysis::BinaryRule::TeamMismatch
            )
        })
        .collect();
    assert!(signer_findings.is_empty(), "{signer_findings:?}");
    // An Xcode development build is signed "Apple Development" with a development profile:
    // the certificate fits, so nothing is reported.
    let mismatch = msec::ios::analysis::analyse_app(ipa.app.as_ref().unwrap(), "2026-10-21")
        .iter()
        .any(|finding| {
            finding.rule == msec::ios::analysis::AppRule::CertificateDistributionMismatch
        });
    let signature = main_signature(&ipa);
    let signer = signature
        .signer
        .expect("an Apple-signed build has a CMS signature");
    assert_eq!(signer.signature, Ok(()));
    assert!(signer.apple_anchored, "{:?}", signer.chain);
    assert_eq!(signer.team_id.as_deref(), Some(team.as_str()));
    assert_eq!(signature.team_id.as_deref(), Some(team.as_str()));
    assert_eq!(signer.chain.len(), 3);
    assert!(!mismatch);
}

/// The analysis findings each fixture's signer gives (msec origin): a CMS signature that does
/// not verify, a chain not anchored to Apple (every fixture: the test root), a team the
/// certificate does not have, and a signing certificate the profile does not list.
#[test]
fn signer_findings() {
    use msec::ios::analysis::{AppRule, BinaryRule, analyse_app, analyse_binaries};
    let signer_rules = [
        BinaryRule::CmsSignatureInvalid,
        BinaryRule::SignerNotApple,
        BinaryRule::TeamMismatch,
    ];
    for (variant, binary_expected, profile_mismatch) in [
        ("fixture", &[][..], false),
        (
            "certificate-development",
            &[BinaryRule::SignerNotApple][..],
            false,
        ),
        (
            "certificate-distribution",
            &[BinaryRule::SignerNotApple][..],
            false,
        ),
        (
            "certificate-not-in-profile",
            &[BinaryRule::SignerNotApple][..],
            true,
        ),
        (
            "certificate-cms-tampered",
            &[BinaryRule::CmsSignatureInvalid][..],
            false,
        ),
        (
            "certificate-team-mismatch",
            &[BinaryRule::SignerNotApple, BinaryRule::TeamMismatch][..],
            false,
        ),
        // Not verified: no signer finding either way (coverage::unchecked reports it).
        ("certificate-ed25519", &[][..], false),
    ] {
        let ipa = read_ipa(&Path::new(FIXTURES).join(format!("ipa/{variant}.ipa")));
        let app = ipa.app.as_ref().unwrap();
        let mut found: Vec<BinaryRule> = analyse_binaries(app)
            .into_iter()
            .filter(|finding| {
                finding.binary.ends_with("/Fixture") && signer_rules.contains(&finding.rule)
            })
            .map(|finding| finding.rule)
            .collect();
        found.sort();
        assert_eq!(found, binary_expected, "{variant}");
        let mismatch = analyse_app(app, "2026-10-21")
            .iter()
            .any(|finding| finding.rule == AppRule::ProfileCertificateMismatch);
        assert_eq!(mismatch, profile_mismatch, "{variant}");
    }
}

/// The certificate must fit the distribution method the profile declares: a development
/// certificate in a development build is expected; one on an App Store build is not.
#[test]
fn certificates_fit_the_profiles_distribution_method() {
    use msec::ios::analysis::{AppRule, analyse_app};
    for (variant, expected) in [
        ("certificate-development", false),
        ("certificate-distribution", false),
        ("certificate-development-app-store", true),
        ("certificate-cms-tampered", false),
        ("fixture", false),
    ] {
        let ipa = read_ipa(&Path::new(FIXTURES).join(format!("ipa/{variant}.ipa")));
        let found = analyse_app(ipa.app.as_ref().unwrap(), "2026-10-21")
            .iter()
            .any(|finding| finding.rule == AppRule::CertificateDistributionMismatch);
        assert_eq!(found, expected, "{variant}");
    }
}

/// A signature msec does not verify is reported as unchecked, with every rule it feeds; the
/// signers msec does verify leave nothing unchecked.
#[test]
fn unverified_signers_are_unchecked() {
    use msec::ios::coverage::{UncheckedCause, UncheckedCheck, unchecked};
    for (variant, expected) in [
        ("certificate-ed25519", true),
        ("certificate-distribution", false),
        ("certificate-cms-tampered", false),
        ("fixture", false),
    ] {
        let ipa = read_ipa(&Path::new(FIXTURES).join(format!("ipa/{variant}.ipa")));
        let parts = unchecked(ipa.app.as_ref().unwrap());
        let found = parts.iter().any(|part| {
            part.check == UncheckedCheck::SignerSignature
                && part.cause == UncheckedCause::UnsupportedAlgorithm
                && part.location.ends_with("/Fixture")
        });
        assert_eq!(found, expected, "{variant}: {parts:?}");
    }
    let keys = UncheckedCheck::SignerSignature.keys();
    for rule in [
        "msec_macho_cms_signature_invalid",
        "msec_macho_signer_not_apple",
        "msec_macho_team_mismatch",
        "msec_ios_profile_certificate_mismatch",
        "msec_ios_certificate_distribution_mismatch",
    ] {
        assert!(keys.contains(&rule), "{rule}");
    }
}
