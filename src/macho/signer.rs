//! Who signed a code signature: the CMS signature over the primary CodeDirectory, verified
//! with the signer's certificate; the certificate chain the signature carries, each link
//! verified with the next certificate's key; whether the chain ends at one of Apple's root
//! certificates; and what Apple's certificate naming says about the signer.
//!
//! - The CMS signature signs the CodeDirectory in slot 0 (Apple's `codesign` signs that one
//!   and lists the hashes of the alternates in a signed attribute). A signature that verifies
//!   shows the CodeDirectory, and through its hashes the code and sealed files, are what the
//!   certificate's key signed.
//! - The chain is built from the certificates the signature carries, by issuer and subject
//!   names, leaf first. It is anchored to Apple when every link verifies and the last
//!   certificate is Apple Root CA, Apple Root CA - G2 or Apple Root CA - G3, by SHA-256 of its
//!   DER (the fingerprints macOS's system root store lists). Revocation and expiry are not
//!   checked against a clock: the report gives the dates.
//! - Apple names signing certificates by their use: `Apple Development:`/`iPhone Developer:`
//!   for development builds, `Apple Distribution:`/`iPhone Distribution:` for App Store, ad hoc
//!   and in-house distribution, `Apple iPhone OS Application Signing` for apps the App Store
//!   re-signed, `Developer ID Application:` for macOS apps outside the Mac App Store. The team
//!   ID is the leaf certificate's organizational unit (the common name's parenthesised ID is
//!   the member's, not the team's).

use der::asn1::{PrintableStringRef, Utf8StringRef};
use der::{Decode, Encode};

use crate::android::signing::certificate::CertificateInfo;
use crate::android::signing::crypto::{self, Hash};
use crate::cms::{self, CmsError, VerifyProblem};

/// SHA-256 of Apple's root certificates (DER), as macOS's system root store lists them:
/// Apple Root CA, Apple Root CA - G2, Apple Root CA - G3.
pub(crate) const APPLE_ROOTS: [&str; 3] = [
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
];

/// Longest chain followed: Apple's chains are three certificates.
const MAX_CHAIN: usize = 8;

/// What an Apple signing certificate is for, from its common name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateUse {
    /// `Apple Development:` or `iPhone Developer:`: development builds.
    Development,
    /// `Apple Distribution:` or `iPhone Distribution:`: App Store, ad hoc and in-house builds.
    Distribution,
    /// `Apple iPhone OS Application Signing`: an app the App Store re-signed.
    AppStore,
    /// `Developer ID Application:`: macOS apps distributed outside the Mac App Store.
    DeveloperId,
    /// Any other name.
    Other,
}

impl CertificateUse {
    fn of(common_name: Option<&str>) -> Self {
        let Some(name) = common_name else {
            return Self::Other;
        };
        if name.starts_with("Apple Development:") || name.starts_with("iPhone Developer:") {
            Self::Development
        } else if name.starts_with("Apple Distribution:")
            || name.starts_with("iPhone Distribution:")
        {
            Self::Distribution
        } else if name == "Apple iPhone OS Application Signing" {
            Self::AppStore
        } else if name.starts_with("Developer ID Application:") {
            Self::DeveloperId
        } else {
            Self::Other
        }
    }

    /// `development`, `distribution`, `app_store`, `developer_id`, `other`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Distribution => "distribution",
            Self::AppStore => "app_store",
            Self::DeveloperId => "developer_id",
            Self::Other => "other",
        }
    }
}

/// Why the CMS signature does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerProblem {
    /// The CMS bytes are not a SignedData msec reads.
    Unreadable(CmsError),
    /// The SignedData has no signer.
    NoSigner,
    /// The code signature has no CodeDirectory to verify against.
    NoCodeDirectory,
    /// The signer's signature does not verify over the CodeDirectory.
    Verify(VerifyProblem),
}

impl SignerProblem {
    /// The signature uses an algorithm or key type msec does not verify: it was not checked,
    /// which says nothing about whether it is valid.
    pub fn unsupported(&self) -> bool {
        matches!(
            self,
            Self::Verify(VerifyProblem::UnsupportedAlgorithm(_) | VerifyProblem::KeyUnsupported)
        )
    }
}

impl std::fmt::Display for SignerProblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(error) => write!(formatter, "{error}"),
            Self::NoSigner => formatter.write_str("the CMS signature has no signer"),
            Self::NoCodeDirectory => formatter.write_str("no CodeDirectory to verify"),
            Self::Verify(VerifyProblem::NoCertificate) => {
                formatter.write_str("the signer's certificate is missing")
            }
            Self::Verify(VerifyProblem::UnsupportedAlgorithm(oid)) => {
                write!(formatter, "unsupported algorithm {oid}")
            }
            Self::Verify(VerifyProblem::SignedAttributesDigestMismatch) => formatter
                .write_str("the signed digest is not the CodeDirectory's: it signs other code"),
            Self::Verify(VerifyProblem::KeyUnsupported) => {
                formatter.write_str("the certificate's key type is not supported")
            }
            Self::Verify(VerifyProblem::SignatureInvalid) => {
                formatter.write_str("the signature does not verify")
            }
        }
    }
}

/// One certificate of the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCertificate {
    /// The certificate.
    pub certificate: CertificateInfo,
    /// Its common name.
    pub common_name: Option<String>,
    /// Its signature verifies with the next certificate's key; `None` for the last one
    /// (whether it signed itself is in [`Signer::anchor`]) or when the algorithm is not
    /// supported.
    pub verified_by_next: Option<bool>,
}

/// Who signed a code signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// Whether the CMS signature verifies over the primary CodeDirectory.
    pub signature: Result<(), SignerProblem>,
    /// The chain, leaf first, as far as issuer names link the certificates carried.
    pub chain: Vec<ChainCertificate>,
    /// Certificates carried that are not in the chain.
    pub unlinked: usize,
    /// The last certificate of the chain is one of Apple's roots and every link verifies.
    pub apple_anchored: bool,
    /// The leaf's common name.
    pub common_name: Option<String>,
    /// The leaf's organizational unit: the team ID in Apple's certificates.
    pub team_id: Option<String>,
    /// What the leaf is for, by Apple's naming.
    pub certificate_use: CertificateUse,
    /// The `signingTime` signed attribute (`yyyy-MM-dd HH:mm:ss` UTC).
    pub signing_time: Option<String>,
}

impl Signer {
    /// Reads and checks a CMS signature (`cms`, the blob wrapper's content) against the
    /// primary CodeDirectory's bytes (`None` when the signature has none).
    pub fn check(cms: &[u8], code_directory: Option<&[u8]>) -> Self {
        let signed = cms::parse(cms);
        let certificates: Vec<Vec<u8>> = signed
            .as_ref()
            .map(|signed| signed.certificates.clone())
            .unwrap_or_default();
        let leaf_der: Option<Vec<u8>> = signed.as_ref().ok().and_then(|signed| {
            signed
                .signers
                .first()
                .and_then(|signer| signed.signer_certificate(signer))
                .map(<[u8]>::to_vec)
        });
        let signature = match (&signed, code_directory) {
            (Err(error), _) => Err(SignerProblem::Unreadable(error.clone())),
            (Ok(_), None) => Err(SignerProblem::NoCodeDirectory),
            (Ok(signed), Some(directory)) => match signed.signers.first() {
                None => Err(SignerProblem::NoSigner),
                Some(signer) => signed
                    .verify(signer, directory)
                    .map(|_| ())
                    .map_err(SignerProblem::Verify),
            },
        };
        let signing_time = signed.as_ref().ok().and_then(|signed| {
            signed
                .signers
                .first()
                .and_then(|signer| signer.signed_attributes.as_ref())
                .and_then(|attributes| attributes.signing_time.clone())
        });
        let chain = leaf_der
            .as_deref()
            .map(|leaf| chain_from(leaf, &certificates))
            .unwrap_or_default();
        let anchored_root = ends_at_apple_root(&chain);
        let links_verify = chain
            .iter()
            .take(chain.len().saturating_sub(1))
            .all(|link| link.verified_by_next == Some(true));
        let leaf_names = leaf_der.as_deref().map(names).unwrap_or_default();
        Self {
            signature,
            unlinked: certificates.len().saturating_sub(chain.len()),
            apple_anchored: anchored_root && links_verify,
            certificate_use: CertificateUse::of(leaf_names.common_name.as_deref()),
            common_name: leaf_names.common_name,
            team_id: leaf_names.organizational_unit,
            signing_time,
            chain,
        }
    }

    /// The leaf certificate.
    pub fn leaf(&self) -> Option<&CertificateInfo> {
        self.chain.first().map(|link| &link.certificate)
    }

    /// The chain ends at one of Apple's roots and no link fails, but some link uses an
    /// algorithm or key msec does not verify: whether Apple issued the certificate was not
    /// established either way.
    pub fn anchor_unverified(&self) -> bool {
        let links = &self.chain[..self.chain.len().saturating_sub(1)];
        !self.apple_anchored
            && ends_at_apple_root(&self.chain)
            && links
                .iter()
                .all(|link| link.verified_by_next != Some(false))
            && links.iter().any(|link| link.verified_by_next.is_none())
    }
}

/// The chain's last certificate is one of Apple's self-signed roots.
fn ends_at_apple_root(chain: &[ChainCertificate]) -> bool {
    chain.last().is_some_and(|last| {
        APPLE_ROOTS.contains(&last.certificate.sha256.as_str())
            && last.certificate.subject == last.certificate.issuer
    })
}

/// From the leaf up: each next certificate is the one whose subject is the current issuer.
pub(crate) fn chain_from(leaf: &[u8], certificates: &[Vec<u8>]) -> Vec<ChainCertificate> {
    let decoded: Vec<(Vec<u8>, CertificateInfo)> = certificates
        .iter()
        .filter_map(|der| Some((der.clone(), CertificateInfo::from_der(der).ok()?)))
        .collect();
    let Ok(mut current) = CertificateInfo::from_der(leaf) else {
        return Vec::new();
    };
    let mut current_der = leaf.to_vec();
    let mut chain = Vec::new();
    while chain.len() < MAX_CHAIN {
        let self_signed = current.subject == current.issuer;
        let issuer = (!self_signed)
            .then(|| {
                decoded
                    .iter()
                    .find(|(der, info)| info.subject == current.issuer && *der != current_der)
            })
            .flatten();
        let verified_by_next =
            issuer.and_then(|(issuer_der, _)| issued_by(&current_der, issuer_der));
        chain.push(ChainCertificate {
            common_name: names(&current_der).common_name,
            certificate: current.clone(),
            verified_by_next,
        });
        match issuer {
            Some((der, info)) if !chain.iter().any(|link| link.certificate.der == *der) => {
                current = info.clone();
                current_der = der.clone();
            }
            _ => break,
        }
    }
    chain
}

/// Whether `issuer`'s key verifies `certificate`'s signature; `None` when the algorithm or
/// key is not supported.
fn issued_by(certificate: &[u8], issuer: &[u8]) -> Option<bool> {
    let parsed = x509_cert::Certificate::from_der(certificate).ok()?;
    let tbs = parsed.tbs_certificate().to_der().ok()?;
    let signature = parsed.signature().as_bytes()?;
    let algorithm = parsed.signature_algorithm().oid.to_string();
    let hash = match algorithm.as_str() {
        "1.2.840.113549.1.1.5" => Hash::Sha1,
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => Hash::Sha256,
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Hash::Sha384,
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => Hash::Sha512,
        _ => return None,
    };
    let issuer_info = CertificateInfo::from_der(issuer).ok()?;
    let primitive = cms::signature_primitive(&algorithm, &issuer_info.public_key.algorithm)?;
    match crypto::verify(primitive, hash, &cms::spki_of(issuer), &tbs, signature) {
        Ok(()) => Some(true),
        Err(crypto::VerifyError::Invalid) => Some(false),
        Err(crypto::VerifyError::UnsupportedKey) => None,
    }
}

/// The OIDs of a certificate's extensions (`2.5.29.19`, Apple's `1.2.840.113635.100.6.58`);
/// empty when it cannot be read.
pub(crate) fn extension_oids(certificate: &[u8]) -> Vec<String> {
    let Ok(parsed) = x509_cert::Certificate::from_der(certificate) else {
        return Vec::new();
    };
    parsed
        .tbs_certificate()
        .extensions()
        .map(|extensions| {
            extensions
                .iter()
                .map(|extension| extension.extn_id.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Default)]
struct Names {
    common_name: Option<String>,
    organizational_unit: Option<String>,
}

/// The subject's first common name and organizational unit.
fn names(certificate: &[u8]) -> Names {
    let Ok(parsed) = x509_cert::Certificate::from_der(certificate) else {
        return Names::default();
    };
    let mut found = Names::default();
    for rdn in parsed.tbs_certificate().subject().iter_rdn() {
        for attribute in rdn.iter() {
            let text = attribute
                .value
                .decode_as::<Utf8StringRef<'_>>()
                .map(|value| value.as_str().to_owned())
                .or_else(|_| {
                    attribute
                        .value
                        .decode_as::<PrintableStringRef<'_>>()
                        .map(|value| value.as_str().to_owned())
                })
                .ok();
            match attribute.oid.to_string().as_str() {
                "2.5.4.3" if found.common_name.is_none() => found.common_name = text,
                "2.5.4.11" if found.organizational_unit.is_none() => {
                    found.organizational_unit = text;
                }
                _ => {}
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_names_say_what_a_certificate_is_for() {
        for (name, expected) in [
            ("Apple Development: A B (X1)", CertificateUse::Development),
            ("iPhone Developer: A B (X1)", CertificateUse::Development),
            ("Apple Distribution: Org (T1)", CertificateUse::Distribution),
            ("iPhone Distribution: Org", CertificateUse::Distribution),
            (
                "Apple iPhone OS Application Signing",
                CertificateUse::AppStore,
            ),
            (
                "Developer ID Application: Org (T1)",
                CertificateUse::DeveloperId,
            ),
            ("Apple Developer", CertificateUse::Other),
        ] {
            assert_eq!(CertificateUse::of(Some(name)), expected, "{name}");
        }
        assert_eq!(CertificateUse::of(None), CertificateUse::Other);
    }

    /// A chain reaching Apple's root with a link msec cannot verify is unverified, not
    /// broken; a link that fails, or a root that is not Apple's, decides it.
    #[test]
    fn anchors_reached_through_unverified_links() {
        let read = |name: &str| {
            let path = format!(
                "{}/tests/fixtures/ios/certificates/{name}",
                env!("CARGO_MANIFEST_DIR")
            );
            CertificateInfo::from_der(&std::fs::read(path).unwrap()).unwrap()
        };
        let mut root = read("root.der");
        root.sha256 = APPLE_ROOTS[0].to_owned();
        let link = |certificate: CertificateInfo, verified_by_next| ChainCertificate {
            certificate,
            common_name: None,
            verified_by_next,
        };
        let signer = |middle, root: CertificateInfo| Signer {
            signature: Ok(()),
            chain: vec![
                link(read("development.der"), Some(true)),
                link(read("wwdr.der"), middle),
                link(root, None),
            ],
            unlinked: 0,
            apple_anchored: false,
            common_name: None,
            team_id: None,
            certificate_use: CertificateUse::Development,
            signing_time: None,
        };
        assert!(signer(None, root.clone()).anchor_unverified());
        assert!(!signer(Some(false), root.clone()).anchor_unverified());
        assert!(!signer(None, read("root.der")).anchor_unverified());
        let mut anchored = signer(Some(true), root);
        assert!(!anchored.anchor_unverified());
        anchored.apple_anchored = true;
        assert!(!anchored.anchor_unverified());
    }

    #[test]
    fn garbage_is_unreadable_not_a_panic() {
        let signer = Signer::check(b"\x30\x03\x02\x01\x00", Some(b"cd"));
        assert!(matches!(
            signer.signature,
            Err(SignerProblem::Unreadable(_))
        ));
        assert!(signer.chain.is_empty());
        assert!(!signer.apple_anchored);
    }
}
