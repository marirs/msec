//! JAR signing (APK Signature Scheme v1): `META-INF/MANIFEST.MF`, `<NAME>.SF` and a PKCS#7
//! signature block `<NAME>.RSA|DSA|EC`, verified the way AOSP `apksig`'s `V1SchemeVerifier`
//! does: the block signs the `.SF`, the `.SF` signs the manifest (whole, or section by
//! section), the manifest lists a digest for every entry.

use std::io::{Read, Seek};

use super::certificate::CertificateInfo;
use super::crypto::{self, Hash};
use crate::archive::ZipArchive;
use crate::cms::{self, SignedData, VerifyProblem};

const META_INF: &str = "META-INF/";
const MANIFEST: &str = "META-INF/MANIFEST.MF";
/// Problems reported per kind before the rest are only counted.
const MAX_ENTRY_PROBLEMS: usize = 20;

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
    match cms::parse(block) {
        Ok(signed) if !signed.signers.is_empty() => verify_block(&signed, sf, &mut signer),
        _ => signer.problems.push(JarProblem::BlockUnreadable),
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

/// The PKCS#7 block signs the `.SF` bytes, directly or through signed attributes (its first
/// signer, as Android reads it).
fn verify_block(signed: &SignedData, sf: &[u8], signer: &mut JarSigner) {
    signer.certificates = signed
        .certificates
        .iter()
        .filter_map(|der| CertificateInfo::from_der(der).ok())
        .collect();
    let first = &signed.signers[0];
    signer.digest = cms::digest_hash(&first.digest_algorithm);
    match signed.verify(first, sf) {
        Ok(_) => {}
        Err(VerifyProblem::NoCertificate) => signer.problems.push(JarProblem::NoCertificate),
        Err(VerifyProblem::UnsupportedAlgorithm(oid)) => {
            signer.problems.push(JarProblem::UnsupportedAlgorithm(oid));
        }
        Err(VerifyProblem::SignedAttributesDigestMismatch) => signer
            .problems
            .push(JarProblem::SignedAttributesDigestMismatch),
        Err(VerifyProblem::KeyUnsupported) => signer.problems.push(JarProblem::KeyUnsupported),
        Err(VerifyProblem::SignatureInvalid) => signer.problems.push(JarProblem::SignatureInvalid),
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
        assert!(cms::parse(b"").is_err());
        assert!(cms::parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
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
