//! CMS (PKCS#7) SignedData, RFC 5652, as code-signing formats use it: JAR signature blocks
//! (detached content, DER) and Apple provisioning profiles (attached content, often BER with
//! indefinite lengths, as `openssl cms -stream` and Apple's tools write them).
//!
//! Read from untrusted bytes: BER lengths are bounded by the input, nesting by
//! a fixed depth, and only what signature verification needs is kept (content, certificates,
//! each signer's algorithms, signed attributes and signature). [`SignedData::verify`] checks a
//! signer's signature over the content with the signer's own certificate; it does not build or
//! check a certificate chain, so a verified signature shows the content is what that
//! certificate's key signed, not that the certificate is trusted.

use der::asn1::ObjectIdentifier;

use crate::android::signing::certificate::CertificateInfo;
use crate::android::signing::crypto::{self, Hash, Primitive, VerifyError};

/// `id-signedData`.
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// `id-messageDigest`, the signed attribute holding the content's digest.
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// `id-signingTime`, the signed attribute holding when the signer says it signed.
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
/// Deepest nesting read; SignedData needs about ten levels.
const MAX_DEPTH: usize = 32;

/// Why bytes are not a SignedData msec can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmsError {
    /// Not a ContentInfo holding SignedData.
    NotSignedData,
    /// The encoding is malformed at the named structure.
    Malformed(&'static str),
}

impl std::fmt::Display for CmsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSignedData => formatter.write_str("not CMS SignedData"),
            Self::Malformed(what) => write!(formatter, "malformed CMS: {what}"),
        }
    }
}

impl std::error::Error for CmsError {}

/// Why a signer's signature does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyProblem {
    /// No certificate for the signer.
    NoCertificate,
    /// A digest or signature algorithm msec does not implement.
    UnsupportedAlgorithm(String),
    /// The signed attributes' message digest is not the content's.
    SignedAttributesDigestMismatch,
    /// The certificate's key is not supported.
    KeyUnsupported,
    /// The signature does not verify.
    SignatureInvalid,
}

/// A SignedData.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData {
    /// `eContentType`.
    pub content_type: String,
    /// `eContent`, its octet-string chunks joined; `None` for detached signatures.
    pub content: Option<Vec<u8>>,
    /// Certificates, DER-encoded.
    pub certificates: Vec<Vec<u8>>,
    /// Signers, in order.
    pub signers: Vec<SignerInfo>,
}

/// A `SignerInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    /// The signer's certificate serial number (issuer-and-serial identifier), when given.
    pub serial: Option<Vec<u8>>,
    /// Digest algorithm OID.
    pub digest_algorithm: String,
    /// Signature algorithm OID.
    pub signature_algorithm: String,
    /// Signed attributes, when present.
    pub signed_attributes: Option<SignedAttributes>,
    /// The signature.
    pub signature: Vec<u8>,
}

/// Signed attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttributes {
    /// The attributes re-encoded as a DER `SET OF`, which is what is signed.
    pub reencoded: Vec<u8>,
    /// The `messageDigest` attribute.
    pub message_digest: Option<Vec<u8>>,
    /// The `signingTime` attribute, `yyyy-MM-dd HH:mm:ss` UTC: when the signer's clock says it
    /// signed (unauthenticated beyond the signer's own signature).
    pub signing_time: Option<String>,
}

impl SignedData {
    /// The certificate whose serial number matches the signer's, else the first.
    pub fn signer_certificate(&self, signer: &SignerInfo) -> Option<&[u8]> {
        self.certificates
            .iter()
            .find(|certificate| {
                signer
                    .serial
                    .as_deref()
                    .is_some_and(|serial| certificate_serial(certificate) == Some(serial))
            })
            .or_else(|| self.certificates.first())
            .map(Vec::as_slice)
    }

    /// Verifies `signer`'s signature over `content` (the attached content, or the detached
    /// bytes a JAR's `.SF` file is). Returns the signer's certificate and the digest used.
    pub fn verify(
        &self,
        signer: &SignerInfo,
        content: &[u8],
    ) -> Result<(CertificateInfo, Hash), VerifyProblem> {
        let certificate = self
            .signer_certificate(signer)
            .and_then(|der| CertificateInfo::from_der(der).ok())
            .ok_or(VerifyProblem::NoCertificate)?;
        let hash = digest_hash(&signer.digest_algorithm)
            .ok_or_else(|| VerifyProblem::UnsupportedAlgorithm(signer.digest_algorithm.clone()))?;
        let primitive = signature_primitive(
            &signer.signature_algorithm,
            &certificate.public_key.algorithm,
        )
        .ok_or_else(|| VerifyProblem::UnsupportedAlgorithm(signer.signature_algorithm.clone()))?;
        let message = match &signer.signed_attributes {
            Some(attributes) => {
                if attributes.message_digest.as_deref()
                    != Some(crypto::digest(hash, content).as_slice())
                {
                    return Err(VerifyProblem::SignedAttributesDigestMismatch);
                }
                attributes.reencoded.clone()
            }
            None => content.to_vec(),
        };
        let spki = spki_of(&certificate.der);
        match crypto::verify(primitive, hash, &spki, &message, &signer.signature) {
            Ok(()) => Ok((certificate, hash)),
            Err(VerifyError::UnsupportedKey) => Err(VerifyProblem::KeyUnsupported),
            Err(VerifyError::Invalid) => Err(VerifyProblem::SignatureInvalid),
        }
    }
}

/// Reads a ContentInfo holding SignedData, BER or DER.
pub fn parse(bytes: &[u8]) -> Result<SignedData, CmsError> {
    let (content_info, _) = read(bytes, 0).ok_or(CmsError::NotSignedData)?;
    let parts = children(&content_info, 0).ok_or(CmsError::NotSignedData)?;
    if parts.first().and_then(oid).as_deref() != Some(OID_SIGNED_DATA) {
        return Err(CmsError::NotSignedData);
    }
    // [0] EXPLICIT SignedData
    let explicit = parts
        .get(1)
        .filter(|part| part.tag == 0xa0)
        .ok_or(CmsError::Malformed("content"))?;
    let signed_data = children(explicit, 1)
        .and_then(|inner| inner.into_iter().next())
        .ok_or(CmsError::Malformed("SignedData"))?;
    let fields = children(&signed_data, 2).ok_or(CmsError::Malformed("SignedData"))?;
    // version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    let encapsulated = fields
        .get(2)
        .filter(|field| field.tag == 0x30)
        .ok_or(CmsError::Malformed("encapsulated content"))?;
    let (content_type, content) = encapsulated_content(encapsulated)?;
    let certificates = fields
        .iter()
        .find(|field| field.tag == 0xa0)
        .and_then(|field| children(field, 3))
        .map(|certificates| {
            certificates
                .iter()
                .filter(|certificate| certificate.tag == 0x30 && certificate.definite)
                .map(|certificate| certificate.raw.to_vec())
                .collect()
        })
        .unwrap_or_default();
    let signer_set = fields
        .iter()
        .rev()
        .find(|field| field.tag == 0x31)
        .ok_or(CmsError::Malformed("signerInfos"))?;
    let signers = children(signer_set, 3)
        .ok_or(CmsError::Malformed("signerInfos"))?
        .iter()
        .filter_map(signer_info)
        .collect();
    Ok(SignedData {
        content_type,
        content,
        certificates,
        signers,
    })
}

fn encapsulated_content(node: &Node<'_>) -> Result<(String, Option<Vec<u8>>), CmsError> {
    let parts = children(node, 3).ok_or(CmsError::Malformed("encapsulated content"))?;
    let content_type = parts
        .first()
        .and_then(oid)
        .ok_or(CmsError::Malformed("content type"))?;
    let content = match parts.get(1) {
        None => None,
        Some(explicit) if explicit.tag == 0xa0 => {
            let inner = children(explicit, 4)
                .and_then(|inner| inner.into_iter().next())
                .ok_or(CmsError::Malformed("content"))?;
            Some(octets(&inner, 5).ok_or(CmsError::Malformed("content octets"))?)
        }
        Some(_) => return Err(CmsError::Malformed("content")),
    };
    Ok((content_type, content))
}

fn signer_info(node: &Node<'_>) -> Option<SignerInfo> {
    let fields = children(node, 4)?;
    // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature, [1]?
    let serial = fields
        .get(1)
        .filter(|sid| sid.tag == 0x30)
        .and_then(|sid| children(sid, 5))
        .and_then(|parts| parts.get(1).map(|serial| serial.value.to_vec()));
    let digest_algorithm = algorithm_oid(fields.get(2)?)?;
    let mut rest = &fields[3..];
    let signed_attributes = match rest.first() {
        Some(attributes) if attributes.tag == 0xa0 => {
            rest = &rest[1..];
            Some(signed_attributes(attributes)?)
        }
        _ => None,
    };
    Some(SignerInfo {
        serial,
        digest_algorithm,
        signature_algorithm: algorithm_oid(rest.first()?)?,
        signed_attributes,
        signature: octets(rest.get(1)?, 5)?,
    })
}

/// Signed attributes must be DER (they are hashed as such); re-encoded as a `SET OF`.
fn signed_attributes(attributes: &Node<'_>) -> Option<SignedAttributes> {
    if !attributes.definite {
        return None;
    }
    let mut reencoded = attributes.raw.to_vec();
    reencoded[0] = 0x31;
    let listed = children(attributes, 5)?;
    let value_of = |wanted: &str| -> Option<Node<'_>> {
        listed.iter().find_map(|attribute| {
            let parts = children(attribute, 6)?;
            if oid(parts.first()?)?.as_str() != wanted {
                return None;
            }
            children(parts.get(1)?, 7)?.into_iter().next()
        })
    };
    let message_digest = value_of(OID_MESSAGE_DIGEST).and_then(|value| octets(&value, 8));
    let signing_time = value_of(OID_SIGNING_TIME).and_then(|value| time(&value));
    Some(SignedAttributes {
        reencoded,
        message_digest,
        signing_time,
    })
}

/// A `UTCTime` (two-digit years: 50 to 99 are 19xx, RFC 5280) or `GeneralizedTime` in UTC
/// (`Z`), as `yyyy-MM-dd HH:mm:ss`. Fractions and offsets are not read.
fn time(node: &Node<'_>) -> Option<String> {
    let text = std::str::from_utf8(node.value).ok()?;
    let digits = text.strip_suffix('Z')?;
    let full = match (node.tag, digits.len()) {
        (0x17, 12) => {
            let year: u32 = digits[..2].parse().ok()?;
            format!("{}{digits}", if year >= 50 { "19" } else { "20" })
        }
        (0x18, 14) => digits.to_owned(),
        _ => return None,
    };
    if !full.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{} {}:{}:{}",
        &full[..4],
        &full[4..6],
        &full[6..8],
        &full[8..10],
        &full[10..12],
        &full[12..14]
    ))
}

/// A BER element.
struct Node<'data> {
    tag: u8,
    /// Definite length (DER-compatible): `raw` is its exact encoding.
    definite: bool,
    /// The contents, without header (and without the end-of-contents octets).
    value: &'data [u8],
    /// The whole encoding.
    raw: &'data [u8],
}

/// Reads one BER element. High tag numbers are not read (CMS does not use them); indefinite
/// lengths are read for constructed elements, to their end-of-contents octets.
fn read(input: &[u8], depth: usize) -> Option<(Node<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let tag = *input.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *input.get(1)?;
    if first == 0x80 {
        // Indefinite: constructed only; children until 00 00.
        if tag & 0x20 == 0 {
            return None;
        }
        let mut rest = &input[2..];
        loop {
            if rest.starts_with(&[0, 0]) {
                let consumed = input.len() - rest.len();
                return Some((
                    Node {
                        tag,
                        definite: false,
                        value: &input[2..consumed],
                        raw: &input[..consumed + 2],
                    },
                    &rest[2..],
                ));
            }
            let (_, next) = read(rest, depth + 1)?;
            rest = next;
        }
    }
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count > 8 {
            return None;
        }
        let length = input
            .get(2..2 + count)?
            .iter()
            .try_fold(0usize, |length, byte| {
                length
                    .checked_mul(256)
                    .map(|value| value | usize::from(*byte))
            })?;
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    let raw = input.get(..end)?;
    Some((
        Node {
            tag,
            definite: true,
            value: &raw[header..],
            raw,
        },
        &input[end..],
    ))
}

fn children<'data>(node: &Node<'data>, depth: usize) -> Option<Vec<Node<'data>>> {
    let mut rest = node.value;
    let mut items = Vec::new();
    while !rest.is_empty() {
        let (item, next) = read(rest, depth + 1)?;
        items.push(item);
        rest = next;
    }
    Some(items)
}

/// An OCTET STRING's bytes, its chunks joined when it is constructed (BER).
fn octets(node: &Node<'_>, depth: usize) -> Option<Vec<u8>> {
    match node.tag {
        0x04 => Some(node.value.to_vec()),
        0x24 => {
            let mut bytes = Vec::new();
            for chunk in children(node, depth)? {
                bytes.extend(octets(&chunk, depth + 1)?);
            }
            Some(bytes)
        }
        _ => None,
    }
}

fn oid(node: &Node<'_>) -> Option<String> {
    (node.tag == 0x06)
        .then(|| {
            ObjectIdentifier::from_bytes(node.value)
                .ok()
                .map(|oid| oid.to_string())
        })
        .flatten()
}

/// The first element of an `AlgorithmIdentifier` sequence.
fn algorithm_oid(node: &Node<'_>) -> Option<String> {
    oid(children(node, MAX_DEPTH - 1)?.first()?)
}

/// The serial number's content bytes in a DER certificate.
fn certificate_serial(certificate: &[u8]) -> Option<&[u8]> {
    let (certificate, _) = read(certificate, 0)?;
    let (tbs, _) = read(certificate.value, 1)?;
    let fields = children(&tbs, 2)?;
    let serial_index = usize::from(fields.first()?.tag == 0xa0);
    fields
        .get(serial_index)
        .filter(|serial| serial.tag == 0x02)
        .map(|serial| serial.value)
}

/// The certificate's `SubjectPublicKeyInfo`, DER.
pub(crate) fn spki_of(certificate: &[u8]) -> Vec<u8> {
    use der::{Decode, Encode};
    x509_cert::Certificate::from_der(certificate)
        .ok()
        .and_then(|certificate| {
            certificate
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()
                .ok()
        })
        .unwrap_or_default()
}

/// The hash of a digest algorithm OID.
pub(crate) fn digest_hash(oid: &str) -> Option<Hash> {
    match oid {
        "1.3.14.3.2.26" => Some(Hash::Sha1),
        "2.16.840.1.101.3.4.2.1" => Some(Hash::Sha256),
        "2.16.840.1.101.3.4.2.2" => Some(Hash::Sha384),
        "2.16.840.1.101.3.4.2.3" => Some(Hash::Sha512),
        _ => None,
    }
}

/// The primitive from the signature algorithm OID; plain `rsaEncryption`/`id-ecPublicKey`/
/// `id-dsa` OIDs mean "the key's algorithm with the digest algorithm".
pub(crate) fn signature_primitive(oid: &str, key_algorithm: &str) -> Option<Primitive> {
    match oid {
        "1.2.840.113549.1.1.1"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.113549.1.1.12"
        | "1.2.840.113549.1.1.13" => Some(Primitive::RsaPkcs1),
        "1.2.840.10045.2.1"
        | "1.2.840.10045.4.1"
        | "1.2.840.10045.4.3.2"
        | "1.2.840.10045.4.3.3"
        | "1.2.840.10045.4.3.4" => Some(Primitive::Ecdsa),
        "1.2.840.10040.4.1"
        | "1.2.840.10040.4.3"
        | "2.16.840.1.101.3.4.3.1"
        | "2.16.840.1.101.3.4.3.2" => Some(Primitive::Dsa),
        _ => match key_algorithm {
            "RSA" => Some(Primitive::RsaPkcs1),
            "EC" => Some(Primitive::Ecdsa),
            "DSA" => Some(Primitive::Dsa),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_not_signed_data() {
        assert_eq!(parse(b""), Err(CmsError::NotSignedData));
        assert_eq!(
            parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]),
            Err(CmsError::NotSignedData)
        );
        // Indefinite length on a primitive element, and an unterminated indefinite one.
        assert!(read(&[0x04, 0x80, 0, 0], 0).is_none());
        assert!(read(&[0x30, 0x80, 0x02, 0x01, 0x01], 0).is_none());
        // Nesting past the limit.
        let mut deep = Vec::new();
        for _ in 0..(MAX_DEPTH + 2) {
            deep.extend([0x30, 0x80]);
        }
        deep.extend(std::iter::repeat_n(0, 2 * (MAX_DEPTH + 2)));
        assert!(read(&deep, 0).is_none());
    }

    #[test]
    fn indefinite_lengths_and_chunked_octets_read() {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "c" } }
        let bytes = [
            0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0,
        ];
        let (sequence, rest) = read(&bytes, 0).unwrap();
        assert!(rest.is_empty() && !sequence.definite);
        let inner = children(&sequence, 0).unwrap();
        assert_eq!(octets(&inner[0], 1).unwrap(), b"abc");
    }
}
