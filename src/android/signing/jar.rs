//! JAR signing (APK Signature Scheme v1): `META-INF/MANIFEST.MF`, `<NAME>.SF` and a PKCS#7
//! signature block `<NAME>.RSA|DSA|EC`, verified the way AOSP `apksig`'s `V1SchemeVerifier`
//! does: the block signs the `.SF`, the `.SF` signs the manifest (whole, or section by
//! section), the manifest lists a digest for every entry.

use std::io::{Read, Seek};

use der::asn1::ObjectIdentifier;

use super::certificate::CertificateInfo;
use super::crypto::{self, Hash, Primitive, VerifyError};
use crate::archive::ZipArchive;

const META_INF: &str = "META-INF/";
const MANIFEST: &str = "META-INF/MANIFEST.MF";
/// Problems reported per kind before the rest are only counted.
const MAX_ENTRY_PROBLEMS: usize = 20;

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// Why a JAR signature (or one signer of it) does not verify.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JarProblem {
    /// No `META-INF/MANIFEST.MF`.
    NoManifest,
    /// The PKCS#7 block cannot be decoded.
    BlockUnreadable,
    /// The block's signer certificate is missing.
    NoCertificate,
    /// Digest or signature algorithm not supported.
    UnsupportedAlgorithm(String),
    /// The key cannot be used with the signature algorithm.
    KeyUnsupported,
    /// The block's signature over the `.SF` does not verify.
    SignatureInvalid,
    /// The signed attributes' message digest is not the `.SF`'s.
    SignedAttributesDigestMismatch,
    /// The `.SF` does not match the manifest: `manifest` for the whole manifest or its main
    /// attributes, else the entry name of the section.
    SignatureFileDigestMismatch(String),
    /// A manifest section the `.SF` does not cover.
    EntryNotInSignatureFile(String),
    /// An entry's content does not match its manifest digest: modified after signing.
    EntryDigestMismatch(String),
    /// The manifest lists an entry the APK does not have.
    EntryMissing(String),
    /// An entry the manifest does not list: not covered by the signature.
    UnsignedEntry(String),
    /// More problems of the same kinds than are listed.
    More(usize),
}

/// One signer (`<NAME>.SF` + block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JarSigner {
    /// Base name (`CERT`).
    pub name: String,
    /// Certificates in the block; the signer's first.
    pub certificates: Vec<CertificateInfo>,
    /// Digest algorithm of the block signature.
    pub digest: Option<Hash>,
    /// `X-Android-APK-Signed` scheme IDs: the APK also has these stronger signatures, so a
    /// verifier that finds them missing knows they were stripped.
    pub android_apk_signed: Vec<u32>,
    /// What failed.
    pub problems: Vec<JarProblem>,
}

/// The v1 signature of an APK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JarSignature {
    /// Signers.
    pub signers: Vec<JarSigner>,
    /// Digest algorithms the manifest uses for entries.
    pub entry_digests: Vec<Hash>,
    /// Manifest-level problems (entry digests, unsigned entries).
    pub problems: Vec<JarProblem>,
}

impl JarSignature {
    /// Every signer verified and every entry is covered and intact.
    pub fn verified(&self) -> bool {
        !self.signers.is_empty()
            && self.problems.is_empty()
            && self.signers.iter().all(|signer| signer.problems.is_empty())
    }
}

/// Reads and verifies the v1 signature; `None` when the APK has no `.SF` file.
pub fn verify_jar<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Option<JarSignature> {
    let signature_files = signature_files(archive);
    if signature_files.is_empty() {
        return None;
    }
    let Some(manifest) = archive.read_by_name(MANIFEST).ok().flatten() else {
        let signers = signature_files
            .into_iter()
            .map(|(name, ..)| unverified_signer(name))
            .collect();
        return Some(JarSignature {
            signers,
            entry_digests: Vec::new(),
            problems: vec![JarProblem::NoManifest],
        });
    };
    let sections = parse_manifest(&manifest);
    let signers = signature_files
        .into_iter()
        .map(|(name, sf, block)| {
            let sf = archive.read_by_name(&sf).ok().flatten().unwrap_or_default();
            let block = archive
                .read_by_name(&block)
                .ok()
                .flatten()
                .unwrap_or_default();
            verify_signer(name, &sf, &block, &manifest, &sections)
        })
        .collect();
    let (entry_digests, problems) = verify_entries(archive, &sections);
    Some(JarSignature {
        signers,
        entry_digests,
        problems,
    })
}

/// `text` without `suffix`, compared ignoring ASCII case. Entry names and attribute keys come
/// from the package and may hold multibyte characters, where cutting at `len - suffix.len()`
/// could split one: the bytes are compared first, and a match with an ASCII suffix makes the cut
/// a character boundary.
fn strip_suffix_ignore_ascii_case<'text>(text: &'text str, suffix: &str) -> Option<&'text str> {
    let cut = text.len().checked_sub(suffix.len())?;
    text.as_bytes()[cut..]
        .eq_ignore_ascii_case(suffix.as_bytes())
        .then(|| text.get(..cut))
        .flatten()
}

fn unverified_signer(name: String) -> JarSigner {
    JarSigner {
        name,
        certificates: Vec::new(),
        digest: None,
        android_apk_signed: Vec::new(),
        problems: Vec::new(),
    }
}

/// `(base name, .SF entry, block entry)` for every top-level `META-INF/*.SF` with a block.
fn signature_files<R: Read + Seek>(archive: &ZipArchive<R>) -> Vec<(String, String, String)> {
    let names: Vec<&str> = archive
        .entries()
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    let mut found = Vec::new();
    for name in &names {
        let Some(file) = name
            .strip_prefix(META_INF)
            .filter(|file| !file.contains('/'))
        else {
            continue;
        };
        let Some(base) = strip_suffix_ignore_ascii_case(file, ".SF") else {
            continue;
        };
        let block = ["RSA", "DSA", "EC"]
            .iter()
            .map(|extension| format!("{META_INF}{base}.{extension}"))
            .find(|candidate| {
                names
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(candidate))
            });
        if let Some(block) = block {
            let block = names
                .iter()
                .find(|name| name.eq_ignore_ascii_case(&block))
                .map(|name| (*name).to_owned())
                .unwrap_or(block);
            found.push((base.to_owned(), (*name).to_owned(), block));
        }
    }
    found
}

fn verify_signer(
    name: String,
    sf: &[u8],
    block: &[u8],
    manifest: &[u8],
    sections: &[ManifestSection<'_>],
) -> JarSigner {
    let mut signer = unverified_signer(name);
    match Pkcs7::parse(block) {
        Some(pkcs7) => verify_block(&pkcs7, sf, &mut signer),
        None => signer.problems.push(JarProblem::BlockUnreadable),
    }
    let sf_sections = parse_manifest(sf);
    if let Some(main) = sf_sections.first() {
        signer.android_apk_signed = attribute(main, "X-Android-APK-Signed")
            .map(|value| {
                value
                    .split(',')
                    .filter_map(|id| id.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default();
    }
    signer
        .problems
        .extend(verify_signature_file(&sf_sections, manifest, sections));
    signer
}

/// The PKCS#7 block signs the `.SF` bytes, directly or through signed attributes.
fn verify_block(pkcs7: &Pkcs7<'_>, sf: &[u8], signer: &mut JarSigner) {
    signer.certificates = pkcs7
        .certificates
        .iter()
        .filter_map(|der| CertificateInfo::from_der(der).ok())
        .collect();
    let Some(certificate) = pkcs7
        .signer_certificate()
        .and_then(|der| CertificateInfo::from_der(der).ok())
    else {
        signer.problems.push(JarProblem::NoCertificate);
        return;
    };
    let Some(hash) = digest_hash(&pkcs7.digest_algorithm) else {
        signer.problems.push(JarProblem::UnsupportedAlgorithm(
            pkcs7.digest_algorithm.clone(),
        ));
        return;
    };
    signer.digest = Some(hash);
    let Some(primitive) = signature_primitive(
        &pkcs7.signature_algorithm,
        &certificate.public_key.algorithm,
    ) else {
        signer.problems.push(JarProblem::UnsupportedAlgorithm(
            pkcs7.signature_algorithm.clone(),
        ));
        return;
    };
    let message = match &pkcs7.signed_attributes {
        Some(attributes) => {
            if attributes.message_digest.as_deref() != Some(crypto::digest(hash, sf).as_slice()) {
                signer
                    .problems
                    .push(JarProblem::SignedAttributesDigestMismatch);
            }
            attributes.reencoded.clone()
        }
        None => sf.to_vec(),
    };
    let spki = spki_of(&certificate.der);
    match crypto::verify(primitive, hash, &spki, &message, &pkcs7.signature) {
        Ok(()) => {}
        Err(VerifyError::UnsupportedKey) => signer.problems.push(JarProblem::KeyUnsupported),
        Err(VerifyError::Invalid) => signer.problems.push(JarProblem::SignatureInvalid),
    }
}

fn spki_of(certificate: &[u8]) -> Vec<u8> {
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

fn digest_hash(oid: &str) -> Option<Hash> {
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
fn signature_primitive(oid: &str, key_algorithm: &str) -> Option<Primitive> {
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

/// `.SF` → manifest: the whole-manifest digest, else the main attributes and every section.
fn verify_signature_file(
    sf: &[ManifestSection<'_>],
    manifest: &[u8],
    sections: &[ManifestSection<'_>],
) -> Vec<JarProblem> {
    let Some(main) = sf.first() else {
        return vec![JarProblem::SignatureFileDigestMismatch(
            "manifest".to_owned(),
        )];
    };
    let whole = digest_attributes(main, "-Digest-Manifest");
    if !whole.is_empty()
        && whole
            .iter()
            .all(|(hash, expected)| crypto::digest(*hash, manifest) == *expected)
    {
        return Vec::new();
    }
    let mut problems = Vec::new();
    let main_attributes = digest_attributes(main, "-Digest-Manifest-Main-Attributes");
    if let Some(manifest_main) = sections.first()
        && main_attributes
            .iter()
            .any(|(hash, expected)| crypto::digest(*hash, manifest_main.raw) != *expected)
    {
        problems.push(JarProblem::SignatureFileDigestMismatch(
            "manifest".to_owned(),
        ));
    }
    for section in sections.iter().skip(1) {
        let Some(name) = &section.name else {
            continue;
        };
        let covered = sf
            .iter()
            .skip(1)
            .find(|candidate| candidate.name.as_deref() == Some(name.as_str()));
        match covered {
            None => problems.push(JarProblem::EntryNotInSignatureFile(name.clone())),
            Some(sf_section) => {
                let digests = digest_attributes(sf_section, "-Digest");
                if digests.is_empty()
                    || digests
                        .iter()
                        .any(|(hash, expected)| crypto::digest(*hash, section.raw) != *expected)
                {
                    problems.push(JarProblem::SignatureFileDigestMismatch(name.clone()));
                }
            }
        }
    }
    cap(problems)
}

/// Manifest → entries: every listed entry exists and matches; every entry is listed.
fn verify_entries<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    sections: &[ManifestSection<'_>],
) -> (Vec<Hash>, Vec<JarProblem>) {
    let mut problems = Vec::new();
    let mut algorithms = Vec::new();
    for section in sections.iter().skip(1) {
        let Some(name) = &section.name else {
            continue;
        };
        let digests = digest_attributes(section, "-Digest");
        for (hash, _) in &digests {
            if !algorithms.contains(hash) {
                algorithms.push(*hash);
            }
        }
        match archive.read_by_name(name) {
            Ok(Some(data)) => {
                if digests
                    .iter()
                    .any(|(hash, expected)| crypto::digest(*hash, &data) != *expected)
                {
                    problems.push(JarProblem::EntryDigestMismatch(name.clone()));
                }
            }
            Ok(None) => problems.push(JarProblem::EntryMissing(name.clone())),
            Err(_) => problems.push(JarProblem::EntryDigestMismatch(name.clone())),
        }
    }
    let listed: Vec<&str> = sections
        .iter()
        .filter_map(|section| section.name.as_deref())
        .collect();
    for entry in archive.entries() {
        if needs_manifest_entry(&entry.name)
            && !entry.is_directory
            && !listed.contains(&entry.name.as_str())
        {
            problems.push(JarProblem::UnsignedEntry(entry.name.clone()));
        }
    }
    (algorithms, cap(problems))
}

/// Everything but directories and the signature files themselves must be in the manifest.
fn needs_manifest_entry(name: &str) -> bool {
    let Some(file) = name.strip_prefix(META_INF) else {
        return true;
    };
    if file.contains('/') {
        return true;
    }
    let upper = file.to_ascii_uppercase();
    !(upper == "MANIFEST.MF"
        || [".SF", ".RSA", ".DSA", ".EC"]
            .iter()
            .any(|extension| upper.ends_with(extension)))
}

fn cap(mut problems: Vec<JarProblem>) -> Vec<JarProblem> {
    if problems.len() > MAX_ENTRY_PROBLEMS {
        let more = problems.len() - MAX_ENTRY_PROBLEMS;
        problems.truncate(MAX_ENTRY_PROBLEMS);
        problems.push(JarProblem::More(more));
    }
    problems
}

// ---------------------------------------------------------------------------------------------
// JAR manifest format
// ---------------------------------------------------------------------------------------------

/// One section: attributes in order, and the exact bytes (including the blank line that ends
/// it), which is what `.SF` digests cover.
pub(crate) struct ManifestSection<'data> {
    name: Option<String>,
    attributes: Vec<(String, String)>,
    raw: &'data [u8],
}

/// Splits a manifest into sections. Lines end with CRLF, LF or CR; a line starting with a space
/// continues the previous one.
pub(crate) fn parse_manifest(bytes: &[u8]) -> Vec<ManifestSection<'_>> {
    let mut sections = Vec::new();
    let mut section_start = 0;
    let mut lines: Vec<String> = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let (line, next) = next_line(bytes, position);
        position = next;
        if line.is_empty() {
            if !lines.is_empty() {
                sections.push(section(
                    std::mem::take(&mut lines),
                    &bytes[section_start..position],
                ));
            }
            section_start = position;
            continue;
        }
        let text = String::from_utf8_lossy(line);
        match (text.strip_prefix(' '), lines.last_mut()) {
            (Some(continuation), Some(previous)) => previous.push_str(continuation),
            _ => lines.push(text.into_owned()),
        }
    }
    if !lines.is_empty() {
        sections.push(section(lines, &bytes[section_start..]));
    }
    sections
}

fn next_line(bytes: &[u8], start: usize) -> (&[u8], usize) {
    let mut end = start;
    while end < bytes.len() && bytes[end] != b'\n' && bytes[end] != b'\r' {
        end += 1;
    }
    let mut next = end;
    if next < bytes.len() && bytes[next] == b'\r' {
        next += 1;
    }
    if next < bytes.len() && bytes[next] == b'\n' {
        next += 1;
    }
    (&bytes[start..end], next)
}

fn section(lines: Vec<String>, raw: &[u8]) -> ManifestSection<'_> {
    let attributes: Vec<(String, String)> = lines
        .into_iter()
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();
    let name = attributes
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("Name"))
        .map(|(_, value)| value.clone());
    ManifestSection {
        name,
        attributes,
        raw,
    }
}

fn attribute<'section>(section: &'section ManifestSection<'_>, key: &str) -> Option<&'section str> {
    section
        .attributes
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        .map(|(_, value)| value.as_str())
}

/// `<ALG><suffix>: base64` attributes (`SHA-256-Digest`, `SHA1-Digest-Manifest`) with known
/// algorithms.
fn digest_attributes(section: &ManifestSection<'_>, suffix: &str) -> Vec<(Hash, Vec<u8>)> {
    section
        .attributes
        .iter()
        .filter_map(|(key, value)| {
            let algorithm = strip_suffix_ignore_ascii_case(key, suffix)?;
            let hash = match algorithm.to_ascii_uppercase().as_str() {
                "SHA1" | "SHA-1" => Hash::Sha1,
                "SHA-256" => Hash::Sha256,
                "SHA-384" => Hash::Sha384,
                "SHA-512" => Hash::Sha512,
                _ => return None,
            };
            Some((hash, base64_decode(value)?))
        })
        .collect()
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| -> Option<u32> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let symbols: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
        .collect();
    let mut out = Vec::with_capacity(symbols.len() * 3 / 4);
    for chunk in symbols.chunks(4) {
        let mut accumulator = 0u32;
        for (index, symbol) in chunk.iter().enumerate() {
            accumulator |= value(*symbol)? << (18 - 6 * index);
        }
        let bytes = accumulator.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// PKCS#7 SignedData, the parts JAR signing uses
// ---------------------------------------------------------------------------------------------

/// A DER element.
struct Tlv<'data> {
    tag: u8,
    value: &'data [u8],
    raw: &'data [u8],
}

/// Reads one DER element (definite lengths only; DER never uses indefinite ones).
fn read_tlv(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let length = input
            .get(2..2 + count)?
            .iter()
            .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    let raw = input.get(..end)?;
    Some((
        Tlv {
            tag,
            value: &raw[header..],
            raw,
        },
        &input[end..],
    ))
}

fn children(value: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut rest = value;
    let mut items = Vec::new();
    while !rest.is_empty() {
        let (item, next) = read_tlv(rest)?;
        items.push(item);
        rest = next;
    }
    Some(items)
}

fn oid(tlv: &Tlv<'_>) -> Option<String> {
    (tlv.tag == 0x06)
        .then(|| {
            ObjectIdentifier::from_bytes(tlv.value)
                .ok()
                .map(|oid| oid.to_string())
        })
        .flatten()
}

/// The first element of an `AlgorithmIdentifier` sequence.
fn algorithm_oid(tlv: &Tlv<'_>) -> Option<String> {
    oid(children(tlv.value)?.first()?)
}

struct SignedAttributes {
    /// The attributes re-encoded as a DER `SET OF`, which is what is signed.
    reencoded: Vec<u8>,
    message_digest: Option<Vec<u8>>,
}

struct Pkcs7<'data> {
    certificates: Vec<&'data [u8]>,
    signer_serial: Option<&'data [u8]>,
    digest_algorithm: String,
    signature_algorithm: String,
    signed_attributes: Option<SignedAttributes>,
    signature: Vec<u8>,
}

impl<'data> Pkcs7<'data> {
    fn parse(bytes: &'data [u8]) -> Option<Self> {
        let (content_info, _) = read_tlv(bytes)?;
        let parts = children(content_info.value)?;
        if oid(parts.first()?)? != OID_SIGNED_DATA {
            return None;
        }
        let (signed_data, _) = read_tlv(parts.get(1)?.value)?;
        let fields = children(signed_data.value)?;
        let certificates = fields
            .iter()
            .find(|field| field.tag == 0xa0)
            .and_then(|field| children(field.value))
            .map(|certificates| {
                certificates
                    .iter()
                    .map(|certificate| certificate.raw)
                    .collect()
            })
            .unwrap_or_default();
        let signer_infos = fields.iter().rev().find(|field| field.tag == 0x31)?;
        let signer = children(signer_infos.value)?.into_iter().next()?;
        Self::from_signer_info(&signer, certificates)
    }

    fn from_signer_info(signer: &Tlv<'data>, certificates: Vec<&'data [u8]>) -> Option<Self> {
        let fields = children(signer.value)?;
        // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature, [1]?
        let signer_serial = fields
            .get(1)
            .filter(|sid| sid.tag == 0x30)
            .and_then(|sid| children(sid.value))
            .and_then(|parts| parts.get(1).map(|serial| serial.value));
        let digest_algorithm = algorithm_oid(fields.get(2)?)?;
        let mut rest = &fields[3..];
        let signed_attributes = match rest.first() {
            Some(attributes) if attributes.tag == 0xa0 => {
                rest = &rest[1..];
                Some(signed_attributes(attributes)?)
            }
            _ => None,
        };
        Some(Self {
            certificates,
            signer_serial,
            digest_algorithm,
            signature_algorithm: algorithm_oid(rest.first()?)?,
            signed_attributes,
            signature: rest
                .get(1)
                .filter(|signature| signature.tag == 0x04)?
                .value
                .to_vec(),
        })
    }

    /// The certificate whose serial number matches the signer's, else the first.
    fn signer_certificate(&self) -> Option<&'data [u8]> {
        let serial = self.signer_serial;
        self.certificates
            .iter()
            .find(|certificate| {
                serial.is_some_and(|serial| certificate_serial(certificate) == Some(serial))
            })
            .or_else(|| self.certificates.first())
            .copied()
    }
}

fn signed_attributes(attributes: &Tlv<'_>) -> Option<SignedAttributes> {
    let mut reencoded = attributes.raw.to_vec();
    reencoded[0] = 0x31;
    let message_digest = children(attributes.value)?.iter().find_map(|attribute| {
        let parts = children(attribute.value)?;
        if oid(parts.first()?)? != OID_MESSAGE_DIGEST {
            return None;
        }
        let values = children(parts.get(1)?.value)?;
        values
            .first()
            .filter(|value| value.tag == 0x04)
            .map(|value| value.value.to_vec())
    });
    Some(SignedAttributes {
        reencoded,
        message_digest,
    })
}

/// The serial number's content bytes in a DER certificate.
fn certificate_serial(certificate: &[u8]) -> Option<&[u8]> {
    let (certificate, _) = read_tlv(certificate)?;
    let (tbs, _) = read_tlv(certificate.value)?;
    let fields = children(tbs.value)?;
    let serial_index = usize::from(fields.first()?.tag == 0xa0);
    fields
        .get(serial_index)
        .filter(|serial| serial.tag == 0x02)
        .map(|serial| serial.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_sections_keep_their_exact_bytes() {
        let manifest = b"Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\nName: res/a-very-long-na\r\n me.xml\r\nSHA-256-Digest: AAAA\r\n\r\nName: b\nSHA1-Digest: AAAA\n";
        let sections = parse_manifest(manifest);
        assert_eq!(sections.len(), 3);
        assert_eq!(
            sections[0].raw,
            b"Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\n"
        );
        assert_eq!(
            sections[1].name.as_deref(),
            Some("res/a-very-long-name.xml")
        );
        assert!(sections[1].raw.ends_with(b"AAAA\r\n\r\n"));
        assert_eq!(sections[2].name.as_deref(), Some("b"));
        assert_eq!(digest_attributes(&sections[1], "-Digest").len(), 1);
    }

    #[test]
    fn base64_decodes_padded_and_unpadded() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8gd29ybGQ").unwrap(), b"hello world");
        assert_eq!(base64_decode("not*base64"), None);
    }

    #[test]
    fn signature_files_exclude_nested_and_signature_entries() {
        assert!(!needs_manifest_entry("META-INF/CERT.SF"));
        assert!(!needs_manifest_entry("META-INF/MANIFEST.MF"));
        assert!(needs_manifest_entry("META-INF/services/x"));
        assert!(needs_manifest_entry("META-INF/androidx.core_core.version"));
        assert!(needs_manifest_entry("classes.dex"));
    }

    #[test]
    fn garbage_blocks_do_not_parse() {
        assert!(Pkcs7::parse(b"").is_none());
        assert!(Pkcs7::parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn suffixes_are_stripped_without_splitting_characters() {
        assert_eq!(
            strip_suffix_ignore_ascii_case("CERT.sf", ".SF"),
            Some("CERT")
        );
        assert_eq!(
            strip_suffix_ignore_ascii_case("SHA-256-Digest", "-Digest"),
            Some("SHA-256")
        );
        // The cut would fall inside the 3-byte U+FFFD: no panic, no match.
        assert_eq!(strip_suffix_ignore_ascii_case("\u{fffd}x", ".SF"), None);
        assert_eq!(
            strip_suffix_ignore_ascii_case("\u{fffd}abcdef", "-Digest"),
            None
        );
        assert_eq!(strip_suffix_ignore_ascii_case("SF", ".SF"), None);
    }
}
