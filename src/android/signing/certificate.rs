//! Signer certificate details (MobSF `cert_analysis.py::get_cert_details` and
//! `get_pub_key_details`), decoded with `x509-cert`.

use der::{Decode, Encode};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;
use x509_cert::time::Time;

use super::crypto::{EcCurve, ec_curve};

/// What `CN=Android Debug` certificates (the SDK's debug keystore) are called; every developer
/// machine has the same kind, and their keys are not protected.
const DEBUG_SUBJECT: &str = "CN=Android Debug";

/// The public key of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// `RSA`, `EC`, `DSA`, or the algorithm OID.
    pub algorithm: String,
    /// Key size in bits (modulus for RSA, field for EC, `p` for DSA).
    pub bits: Option<u32>,
    /// Named curve for EC keys (`P-256`).
    pub curve: Option<&'static str>,
    /// SHA-256 of the DER `SubjectPublicKeyInfo`.
    pub sha256: String,
}

/// A decoded X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// Subject distinguished name (RFC 4514).
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number, hex.
    pub serial: String,
    /// Start of validity, `yyyy-MM-dd HH:mm:ss` UTC.
    pub not_before: String,
    /// End of validity, `yyyy-MM-dd HH:mm:ss` UTC.
    pub not_after: String,
    /// Certificate signature algorithm (`SHA256withRSA`), or its OID when unknown.
    pub signature_algorithm: String,
    /// Hash of the certificate signature algorithm (`sha1`, `sha256`, `md5`), as MobSF reports it.
    pub hash_algorithm: Option<&'static str>,
    /// Public key.
    pub public_key: PublicKeyInfo,
    /// Fingerprints of the DER certificate.
    pub sha256: String,
    /// SHA-1 fingerprint.
    pub sha1: String,
    /// MD5 fingerprint.
    pub md5: String,
    /// The DER encoding.
    pub der: Vec<u8>,
}

impl CertificateInfo {
    /// Decodes a DER certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, der::Error> {
        let certificate = Certificate::from_der(der)?;
        let tbs = certificate.tbs_certificate();
        let algorithm_oid = certificate.signature_algorithm().oid.to_string();
        let (signature_algorithm, hash_algorithm) = signature_algorithm_name(&algorithm_oid);
        let spki = tbs.subject_public_key_info().to_der()?;
        Ok(Self {
            subject: tbs.subject().to_string(),
            issuer: tbs.issuer().to_string(),
            serial: hex(tbs.serial_number().as_bytes()),
            not_before: format_time(&tbs.validity().not_before),
            not_after: format_time(&tbs.validity().not_after),
            signature_algorithm: signature_algorithm.map_or(algorithm_oid, str::to_owned),
            hash_algorithm,
            public_key: public_key_info(&spki),
            sha256: hex(&Sha256::digest(der)),
            sha1: hex(&Sha1::digest(der)),
            md5: hex(&Md5::digest(der)),
            der: der.to_vec(),
        })
    }

    /// Signed with the Android SDK's debug keystore.
    pub fn is_debug(&self) -> bool {
        self.subject
            .split(',')
            .any(|part| part.trim() == DEBUG_SUBJECT)
            || self.subject.contains(DEBUG_SUBJECT)
    }

    /// Issuer equals subject.
    pub fn is_self_signed(&self) -> bool {
        self.subject == self.issuer
    }

    /// The validity has ended before `today` (`yyyy-MM-dd`).
    pub fn has_expired(&self, today: &str) -> bool {
        self.not_after.get(..10).is_some_and(|date| date < today)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn format_time(time: &Time) -> String {
    let at = time.to_date_time();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        at.year(),
        at.month(),
        at.day(),
        at.hour(),
        at.minutes(),
        at.seconds()
    )
}

/// `(name, hash)` for certificate signature algorithm OIDs.
fn signature_algorithm_name(oid: &str) -> (Option<&'static str>, Option<&'static str>) {
    match oid {
        "1.2.840.113549.1.1.2" => (Some("MD2withRSA"), Some("md2")),
        "1.2.840.113549.1.1.4" => (Some("MD5withRSA"), Some("md5")),
        "1.2.840.113549.1.1.5" => (Some("SHA1withRSA"), Some("sha1")),
        "1.2.840.113549.1.1.11" => (Some("SHA256withRSA"), Some("sha256")),
        "1.2.840.113549.1.1.12" => (Some("SHA384withRSA"), Some("sha384")),
        "1.2.840.113549.1.1.13" => (Some("SHA512withRSA"), Some("sha512")),
        "1.2.840.113549.1.1.10" => (Some("RSASSA-PSS"), None),
        "1.2.840.10045.4.1" => (Some("SHA1withECDSA"), Some("sha1")),
        "1.2.840.10045.4.3.2" => (Some("SHA256withECDSA"), Some("sha256")),
        "1.2.840.10045.4.3.3" => (Some("SHA384withECDSA"), Some("sha384")),
        "1.2.840.10045.4.3.4" => (Some("SHA512withECDSA"), Some("sha512")),
        "1.2.840.10040.4.3" => (Some("SHA1withDSA"), Some("sha1")),
        "2.16.840.1.101.3.4.3.2" => (Some("SHA256withDSA"), Some("sha256")),
        _ => (None, None),
    }
}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_DSA: &str = "1.2.840.10040.4.1";

/// Algorithm, size and fingerprint of a DER `SubjectPublicKeyInfo`.
pub fn public_key_info(spki: &[u8]) -> PublicKeyInfo {
    let sha256 = hex(&Sha256::digest(spki));
    let oid = SubjectPublicKeyInfoRef::try_from(spki)
        .map(|info| info.algorithm.oid.to_string())
        .unwrap_or_default();
    match oid.as_str() {
        OID_RSA => {
            use rsa::traits::PublicKeyParts;
            use spki::DecodePublicKey;
            let bits = rsa::RsaPublicKey::from_public_key_der(spki)
                .ok()
                .map(|key| key.n().bits());
            PublicKeyInfo {
                algorithm: "RSA".to_owned(),
                bits,
                curve: None,
                sha256,
            }
        }
        OID_EC => {
            let curve = ec_curve(spki);
            let (bits, name) = match curve {
                Some(EcCurve::P256) => (Some(256), Some("P-256")),
                Some(EcCurve::P384) => (Some(384), Some("P-384")),
                Some(EcCurve::P521) => (Some(521), Some("P-521")),
                None => (None, None),
            };
            PublicKeyInfo {
                algorithm: "EC".to_owned(),
                bits,
                curve: name,
                sha256,
            }
        }
        OID_DSA => {
            let bits = SubjectPublicKeyInfoRef::try_from(spki)
                .ok()
                .and_then(|info| dsa::VerifyingKey::try_from(info).ok())
                .map(|key| key.components().p().bits());
            PublicKeyInfo {
                algorithm: "DSA".to_owned(),
                bits,
                curve: None,
                sha256,
            }
        }
        other => PublicKeyInfo {
            algorithm: other.to_owned(),
            bits: None,
            curve: None,
            sha256,
        },
    }
}
