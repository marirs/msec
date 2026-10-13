//! APK Signature Scheme v2, v3 and v3.1 signers: parsing and verification, following AOSP
//! `apksig` (`V2SchemeVerifier`, `V3SchemeVerifier`).
//!
//! Every field is a little-endian `u32` or a `u32`-length-prefixed byte string. A signer
//! verifies when every signature with a known algorithm verifies over the signed data, the
//! digests and signatures name the same algorithms, the public key is the first certificate's,
//! and every computed content digest matches.

use super::certificate::{CertificateInfo, PublicKeyInfo, public_key_info};
use super::crypto::{ContentDigest, SignatureAlgorithm, VerifyError, verify};
use super::digest::{ContentDigests, DigestProblem};

/// v2 additional attribute: the APK also has a v3 (or later) signature, so a v2-only result
/// means a stronger signature was stripped.
const STRIPPING_PROTECTION_ATTRIBUTE: u32 = 0xbeef_f00d;
/// v3 additional attribute: the signer's proof-of-rotation lineage (previous signing keys).
const PROOF_OF_ROTATION_ATTRIBUTE: u32 = 0x3ba0_6f8c;

/// Which scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// v2 (Android 7.0 and later).
    V2,
    /// v3 (Android 9 and later).
    V3,
    /// v3.1 (Android 13 and later).
    V31,
}

impl Scheme {
    /// `v2`, `v3`, `v3.1`.
    pub fn label(self) -> &'static str {
        match self {
            Self::V2 => "v2",
            Self::V3 => "v3",
            Self::V31 => "v3.1",
        }
    }
}

/// A signature algorithm as recorded: the raw ID and, when known, the algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgorithmId {
    /// Raw ID.
    pub id: u32,
    /// Known algorithm.
    pub algorithm: Option<SignatureAlgorithm>,
}

/// Why a signer (or a whole scheme block) does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerProblem {
    /// The block or a signer is malformed.
    Malformed(&'static str),
    /// The scheme block lists no signers.
    NoSigners,
    /// No signatures.
    NoSignatures,
    /// No signature uses an algorithm msec (and Android) knows.
    NoKnownAlgorithm,
    /// A signature does not verify over the signed data.
    SignatureInvalid(SignatureAlgorithm),
    /// The public key cannot be used with the signature algorithm.
    KeyUnsupported(SignatureAlgorithm),
    /// Digests and signatures name different algorithms.
    AlgorithmsMismatch,
    /// No certificate.
    NoCertificates,
    /// A certificate cannot be decoded.
    CertificateUnreadable,
    /// The signer's public key is not the first certificate's.
    PublicKeyMismatch,
    /// The APK content does not match the signed digest: the APK was modified after signing.
    DigestMismatch(SignatureAlgorithm),
    /// The content digest could not be computed.
    ContentDigestUnavailable(DigestProblem),
    /// v3: the signer's SDK range differs between its signed and unsigned parts.
    SdkRangeMismatch,
}

/// One signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeSigner {
    /// Certificates; the first is the signer's.
    pub certificates: Vec<CertificateInfo>,
    /// Signature algorithms used.
    pub algorithms: Vec<AlgorithmId>,
    /// The signer's public key.
    pub public_key: PublicKeyInfo,
    /// v3: lowest Android API level this signer applies to.
    pub min_sdk: Option<u32>,
    /// v3: highest Android API level this signer applies to.
    pub max_sdk: Option<u32>,
    /// v3: proof-of-rotation lineage present (the signing key was rotated).
    pub key_rotation: bool,
    /// v2: stripping protection says a v3 (or later) signature exists.
    pub declares_v3: bool,
    /// Verity digests (fs-verity Merkle tree) present but not recomputed by msec.
    pub unchecked_digests: Vec<SignatureAlgorithm>,
    /// What failed; empty when the signer verifies.
    pub problems: Vec<SignerProblem>,
}

impl SchemeSigner {
    /// The signer verified.
    pub fn verified(&self) -> bool {
        self.problems.is_empty()
    }
}

/// One scheme block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemeReport {
    /// The scheme.
    pub scheme: Scheme,
    /// Signers.
    pub signers: Vec<SchemeSigner>,
    /// Block-level problems.
    pub problems: Vec<SignerProblem>,
}

impl SchemeReport {
    /// Every signer verified and nothing is wrong with the block.
    pub fn verified(&self) -> bool {
        self.problems.is_empty()
            && !self.signers.is_empty()
            && self.signers.iter().all(SchemeSigner::verified)
    }

    /// Content digests the signers need, for computing them in one pass.
    pub fn needed_digests(value: &[u8], scheme: Scheme) -> (bool, bool) {
        let signers = parse_signers(value, scheme).unwrap_or_default();
        let kinds: Vec<ContentDigest> = signers
            .iter()
            .flat_map(|signer| &signer.digests)
            .filter_map(|(id, _)| SignatureAlgorithm::from_id(*id))
            .map(SignatureAlgorithm::content_digest)
            .collect();
        (
            kinds.contains(&ContentDigest::ChunkedSha256),
            kinds.contains(&ContentDigest::ChunkedSha512),
        )
    }
}

/// Little-endian reader over length-prefixed fields.
struct Fields<'data> {
    bytes: &'data [u8],
}

impl<'data> Fields<'data> {
    fn new(bytes: &'data [u8]) -> Self {
        Self { bytes }
    }

    fn u32(&mut self) -> Option<u32> {
        let value = u32::from_le_bytes(self.bytes.get(..4)?.try_into().ok()?);
        self.bytes = &self.bytes[4..];
        Some(value)
    }

    fn prefixed(&mut self) -> Option<&'data [u8]> {
        let length = self.u32()? as usize;
        let value = self.bytes.get(..length)?;
        self.bytes = &self.bytes[length..];
        Some(value)
    }

    fn rest(self) -> &'data [u8] {
        self.bytes
    }
}

/// A `u32`-length-prefixed sequence of length-prefixed items.
fn sequence(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let mut fields = Fields::new(bytes);
    let mut items = Vec::new();
    while !fields.bytes.is_empty() {
        items.push(fields.prefixed()?);
    }
    Some(items)
}

/// `(u32 algorithm, prefixed bytes)` items.
fn algorithm_values(bytes: &[u8]) -> Option<Vec<(u32, Vec<u8>)>> {
    sequence(bytes)?
        .into_iter()
        .map(|item| {
            let mut fields = Fields::new(item);
            Some((fields.u32()?, fields.prefixed()?.to_vec()))
        })
        .collect()
}

/// A signer as stored, before verification.
#[derive(Default)]
struct RawSigner<'data> {
    signed_data: &'data [u8],
    digests: Vec<(u32, Vec<u8>)>,
    certificates: Vec<&'data [u8]>,
    attributes: Vec<(u32, &'data [u8])>,
    signed_sdk_range: Option<(u32, u32)>,
    outer_sdk_range: Option<(u32, u32)>,
    signatures: Vec<(u32, Vec<u8>)>,
    public_key: &'data [u8],
}

fn parse_signers(value: &[u8], scheme: Scheme) -> Option<Vec<RawSigner<'_>>> {
    let signers = Fields::new(value).prefixed()?;
    sequence(signers)?
        .into_iter()
        .map(|signer| parse_signer(signer, scheme))
        .collect()
}

fn parse_signer(bytes: &[u8], scheme: Scheme) -> Option<RawSigner<'_>> {
    let mut fields = Fields::new(bytes);
    let signed_data = fields.prefixed()?;
    let outer_sdk_range = match scheme {
        Scheme::V2 => None,
        Scheme::V3 | Scheme::V31 => Some((fields.u32()?, fields.u32()?)),
    };
    let signatures = algorithm_values(fields.prefixed()?)?;
    let public_key = fields.prefixed()?;

    let mut data = Fields::new(signed_data);
    let digests = algorithm_values(data.prefixed()?)?;
    let certificates = sequence(data.prefixed()?)?;
    let signed_sdk_range = match scheme {
        Scheme::V2 => None,
        Scheme::V3 | Scheme::V31 => Some((data.u32()?, data.u32()?)),
    };
    let attributes = sequence(data.prefixed()?)?
        .into_iter()
        .map(|attribute| {
            let mut attribute = Fields::new(attribute);
            Some((attribute.u32()?, attribute.rest()))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(RawSigner {
        signed_data,
        digests,
        certificates,
        attributes,
        signed_sdk_range,
        outer_sdk_range,
        signatures,
        public_key,
    })
}

/// Parses and verifies a scheme block value against the APK's content digests.
pub fn verify_scheme(
    value: &[u8],
    scheme: Scheme,
    digests: &Result<ContentDigests, DigestProblem>,
) -> SchemeReport {
    let Some(signers) = parse_signers(value, scheme) else {
        return SchemeReport {
            scheme,
            signers: Vec::new(),
            problems: vec![SignerProblem::Malformed("signer list")],
        };
    };
    let problems = if signers.is_empty() {
        vec![SignerProblem::NoSigners]
    } else {
        Vec::new()
    };
    let signers = signers
        .iter()
        .map(|signer| verify_signer(signer, digests))
        .collect();
    SchemeReport {
        scheme,
        signers,
        problems,
    }
}

fn verify_signer(
    raw: &RawSigner<'_>,
    digests: &Result<ContentDigests, DigestProblem>,
) -> SchemeSigner {
    let mut problems = Vec::new();
    let algorithms: Vec<AlgorithmId> = raw
        .signatures
        .iter()
        .map(|(id, _)| AlgorithmId {
            id: *id,
            algorithm: SignatureAlgorithm::from_id(*id),
        })
        .collect();
    check_signatures(raw, &mut problems);
    let certificates = check_certificates(raw, &mut problems);
    let unchecked_digests = check_digests(raw, digests, &mut problems);
    if raw.signed_sdk_range != raw.outer_sdk_range {
        problems.push(SignerProblem::SdkRangeMismatch);
    }
    let attribute = |id: u32| raw.attributes.iter().any(|(attribute, _)| *attribute == id);
    SchemeSigner {
        certificates,
        algorithms,
        public_key: public_key_info(raw.public_key),
        min_sdk: raw.signed_sdk_range.map(|(min, _)| min),
        max_sdk: raw.signed_sdk_range.map(|(_, max)| max),
        key_rotation: attribute(PROOF_OF_ROTATION_ATTRIBUTE),
        declares_v3: attribute(STRIPPING_PROTECTION_ATTRIBUTE),
        unchecked_digests,
        problems,
    }
}

fn check_signatures(raw: &RawSigner<'_>, problems: &mut Vec<SignerProblem>) {
    if raw.signatures.is_empty() {
        problems.push(SignerProblem::NoSignatures);
        return;
    }
    let mut known = 0;
    for (id, signature) in &raw.signatures {
        let Some(algorithm) = SignatureAlgorithm::from_id(*id) else {
            continue;
        };
        known += 1;
        let (primitive, hash) = algorithm.parts();
        match verify(primitive, hash, raw.public_key, raw.signed_data, signature) {
            Ok(()) => {}
            Err(VerifyError::UnsupportedKey) => {
                problems.push(SignerProblem::KeyUnsupported(algorithm))
            }
            Err(VerifyError::Invalid) => problems.push(SignerProblem::SignatureInvalid(algorithm)),
        }
    }
    if known == 0 {
        problems.push(SignerProblem::NoKnownAlgorithm);
    }
    let mut signed: Vec<u32> = raw.signatures.iter().map(|(id, _)| *id).collect();
    let mut digested: Vec<u32> = raw.digests.iter().map(|(id, _)| *id).collect();
    signed.sort_unstable();
    digested.sort_unstable();
    if signed != digested {
        problems.push(SignerProblem::AlgorithmsMismatch);
    }
}

fn check_certificates(
    raw: &RawSigner<'_>,
    problems: &mut Vec<SignerProblem>,
) -> Vec<CertificateInfo> {
    if raw.certificates.is_empty() {
        problems.push(SignerProblem::NoCertificates);
        return Vec::new();
    }
    let decoded: Vec<CertificateInfo> = raw
        .certificates
        .iter()
        .filter_map(|der| CertificateInfo::from_der(der).ok())
        .collect();
    if decoded.len() != raw.certificates.len() {
        problems.push(SignerProblem::CertificateUnreadable);
    }
    if let Some(first) = decoded.first()
        && first.public_key.sha256 != public_key_info(raw.public_key).sha256
    {
        problems.push(SignerProblem::PublicKeyMismatch);
    }
    decoded
}

/// Compares every signed digest msec can compute; returns the verity ones it cannot.
fn check_digests(
    raw: &RawSigner<'_>,
    computed: &Result<ContentDigests, DigestProblem>,
    problems: &mut Vec<SignerProblem>,
) -> Vec<SignatureAlgorithm> {
    let mut unchecked = Vec::new();
    for (id, signed_digest) in &raw.digests {
        let Some(algorithm) = SignatureAlgorithm::from_id(*id) else {
            continue;
        };
        let computed = match computed {
            Ok(computed) => computed,
            Err(problem) => {
                problems.push(SignerProblem::ContentDigestUnavailable(problem.clone()));
                return unchecked;
            }
        };
        match computed.get(algorithm.content_digest()) {
            Some(digest) if digest == signed_digest.as_slice() => {}
            Some(_) => problems.push(SignerProblem::DigestMismatch(algorithm)),
            None => unchecked.push(algorithm),
        }
    }
    unchecked
}
