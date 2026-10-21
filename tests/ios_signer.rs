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
    assert_eq!(readings.len(), 5);
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
    let signature = main_signature(&read_ipa(Path::new(&path)));
    let signer = signature
        .signer
        .expect("an Apple-signed build has a CMS signature");
    assert_eq!(signer.signature, Ok(()));
    assert!(signer.apple_anchored, "{:?}", signer.chain);
    assert_eq!(signer.team_id.as_deref(), Some(team.as_str()));
    assert_eq!(signature.team_id.as_deref(), Some(team.as_str()));
    assert_eq!(signer.chain.len(), 3);
}
