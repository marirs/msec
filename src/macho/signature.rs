//! The embedded code signature (`LC_CODE_SIGNATURE`): a SuperBlob of the CodeDirectory (and
//! alternates), the requirements, the entitlements (XML and DER), and the CMS signature, all
//! big-endian. Read the way `codesign -d` reads them; the tests compare identifier, team, flags,
//! version, slot counts, CDHash and entitlements with `codesign -dvvv` on the fixtures.
//!
//! [`CodeDirectory::verify_pages`] recomputes every page hash, as `codesign --verify` does for
//! the code, and [`CodeDirectory::verify_special`] checks a special slot (Info.plist, resources,
//! requirements, entitlements) against bytes the caller supplies. The CMS signature's
//! certificates are not read yet: a CodeDirectory whose hashes all match proves the binary is
//! unchanged since it was signed, not who signed it.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use super::read_u32_be;
use crate::plist::{self, Plist, PlistError};

/// Blob magics.
const SUPERBLOB: u32 = 0xfade_0cc0;
const CODE_DIRECTORY: u32 = 0xfade_0c02;
const REQUIREMENTS: u32 = 0xfade_0c01;
const ENTITLEMENTS: u32 = 0xfade_7171;
const DER_ENTITLEMENTS: u32 = 0xfade_7172;
const BLOB_WRAPPER: u32 = 0xfade_0b01;

/// Slots (blob types in the SuperBlob index; special slots of the CodeDirectory).
pub const SLOT_CODE_DIRECTORY: u32 = 0;
/// `Info.plist`'s hash (special slot 1).
pub const SLOT_INFO_PLIST: u32 = 1;
/// The requirements blob.
pub const SLOT_REQUIREMENTS: u32 = 2;
/// `_CodeSignature/CodeResources`'s hash (special slot 3).
pub const SLOT_RESOURCES: u32 = 3;
/// The entitlements blob (XML).
pub const SLOT_ENTITLEMENTS: u32 = 5;
/// The entitlements blob (DER).
pub const SLOT_DER_ENTITLEMENTS: u32 = 7;
const SLOT_ALTERNATE_FIRST: u32 = 0x1000;
const SLOT_ALTERNATE_LAST: u32 = 0x1004;
const SLOT_CMS: u32 = 0x10000;

/// CodeDirectory flags.
const CS_ADHOC: u32 = 0x2;
const CS_LINKER_SIGNED: u32 = 0x2_0000;
const CS_RUNTIME: u32 = 0x1_0000;

/// More index entries than a signature has in practice; beyond it, the rest are not read.
const MAX_BLOBS: usize = 64;
/// Code slots one CodeDirectory may declare: a 4 GiB image at 4 KiB pages.
const MAX_CODE_SLOTS: u32 = 1 << 20;

/// Why a signature could not be read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Not an embedded-signature SuperBlob.
    NotSuperBlob,
    /// The SuperBlob's header or length does not fit in the signature data.
    Truncated,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotSuperBlob => "not an embedded code signature",
            Self::Truncated => "code signature truncated",
        })
    }
}

impl std::error::Error for SignatureError {}

/// Something malformed in a signature that did not stop reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureAnomaly {
    /// An index entry points outside the SuperBlob, or its blob's length does.
    BlobOutOfBounds {
        /// The slot.
        slot: u32,
    },
    /// A blob's magic is not the one its slot calls for.
    UnexpectedMagic {
        /// The slot.
        slot: u32,
        /// The magic found.
        magic: u32,
    },
    /// A slot appears twice in the index (only the first is read).
    DuplicateSlot {
        /// The slot.
        slot: u32,
    },
    /// More index entries than msec reads.
    TooManyBlobs,
    /// A CodeDirectory field points outside the CodeDirectory, or its slot counts exceed what
    /// it holds.
    InvalidCodeDirectory {
        /// The slot.
        slot: u32,
        /// What.
        reason: &'static str,
    },
}

/// An embedded code signature.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeSignature {
    /// CodeDirectories: slot 0 first, then the alternates (SHA-256 next to SHA-1, ...). Empty
    /// when none could be read: the signature then signs nothing.
    pub code_directories: Vec<CodeDirectory>,
    /// The requirements blob, whole (as hashed into special slot 2).
    pub requirements: Option<Vec<u8>>,
    /// The XML entitlements, when present.
    pub entitlements: Option<Entitlements>,
    /// The DER entitlements blob, whole (as hashed into special slot 7). Not decoded yet.
    pub der_entitlements: Option<Vec<u8>>,
    /// The CMS signature's bytes (inside its wrapper); empty for an ad-hoc signature.
    pub cms: Option<Vec<u8>>,
    /// Problems that did not stop reading.
    pub anomalies: Vec<SignatureAnomaly>,
}

/// XML entitlements.
#[derive(Debug, Clone, PartialEq)]
pub struct Entitlements {
    /// The blob, whole (as hashed into special slot 5).
    pub blob: Vec<u8>,
    /// The plist, read as iOS reads it.
    pub plist: Result<Plist, PlistError>,
}

/// A CodeDirectory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeDirectory {
    /// Its slot (0, or 0x1000.. for alternates).
    pub slot: u32,
    /// `version` (`0x20400`).
    pub version: u32,
    /// `flags` (`0x2` ad hoc, `0x20000` linker-signed, `0x10000` hardened runtime).
    pub flags: u32,
    /// Hash type: 1 SHA-1, 2 SHA-256, 3 SHA-256 truncated to 20 bytes, 4 SHA-384.
    pub hash_type: u8,
    /// Hash size in bytes.
    pub hash_size: u8,
    /// Page size, as a power of two (12: 4 KiB); 0 means one page for all the code.
    pub page_size_log2: u8,
    /// Special slots (hashes before the code hashes).
    pub special_slots: u32,
    /// Code slots (one hash per page).
    pub code_slots: u32,
    /// Bytes of the image the code hashes cover.
    pub code_limit: u64,
    /// The signing identifier (`dev.appchk.fixture`).
    pub identifier: String,
    /// The team identifier, when signed with a team's certificate.
    pub team_id: Option<String>,
    /// `platform` (non-zero for Apple's own binaries).
    pub platform: u8,
    /// `execSegFlags` (v0x20400+): `0x1` main binary, `0x10` allow unsigned pages, ...
    pub exec_segment_flags: Option<u64>,
    /// `runtime` (v0x20500+): the hardened-runtime SDK version.
    pub runtime: Option<u32>,
    /// The CodeDirectory's own bytes.
    blob: Vec<u8>,
    /// Offset of code slot 0 in `blob`.
    hash_offset: usize,
}

/// The outcome of [`CodeDirectory::verify_pages`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageVerification {
    /// Pages hashed.
    pub checked: usize,
    /// Pages whose hash differs (first 32).
    pub mismatched: Vec<usize>,
    /// Why the pages could not all be checked (code limit past the image, unknown hash).
    pub problem: Option<&'static str>,
}

impl PageVerification {
    /// Every page was checked and matches.
    pub fn valid(&self) -> bool {
        self.problem.is_none() && self.mismatched.is_empty()
    }
}

impl CodeSignature {
    /// The CodeDirectory iOS chooses: the strongest hash (SHA-384, then SHA-256, then the
    /// truncated SHA-256, then SHA-1), as `codesign` picks its CDHash.
    pub fn best_code_directory(&self) -> Option<&CodeDirectory> {
        let rank = |hash_type: u8| match hash_type {
            4 => 4,
            2 => 3,
            3 => 2,
            1 => 1,
            _ => 0,
        };
        self.code_directories
            .iter()
            .max_by_key(|directory| rank(directory.hash_type))
    }

    /// Signed with a certificate: the CMS signature holds data. Ad-hoc signatures have an
    /// empty wrapper or none.
    pub fn has_cms_signature(&self) -> bool {
        self.cms.as_ref().is_some_and(|cms| !cms.is_empty())
    }
}

impl CodeDirectory {
    /// The CodeDirectory's own bytes: what a CMS signature signs and the CDHash hashes.
    pub fn bytes(&self) -> &[u8] {
        &self.blob
    }

    /// `CS_ADHOC`: no certificate signs it.
    pub fn is_adhoc(&self) -> bool {
        self.flags & CS_ADHOC != 0
    }

    /// `CS_LINKER_SIGNED`: the linker's automatic ad-hoc signature (no resources sealed).
    pub fn is_linker_signed(&self) -> bool {
        self.flags & CS_LINKER_SIGNED != 0
    }

    /// `CS_RUNTIME`: the hardened runtime.
    pub fn hardened_runtime(&self) -> bool {
        self.flags & CS_RUNTIME != 0
    }

    /// The CodeDirectory's size in bytes (`codesign`'s `size=`).
    pub fn size(&self) -> usize {
        self.blob.len()
    }

    /// The CDHash: this CodeDirectory's hash, truncated to 20 bytes, in hex (`codesign`'s
    /// `CDHash=`). `None` for an unknown hash type.
    pub fn cdhash(&self) -> Option<String> {
        let digest = hash(self.hash_type, &self.blob)?;
        Some(hex(&digest[..20.min(digest.len())]))
    }

    /// The hash stored for special slot `slot` (1 Info.plist, 2 requirements, 3 resources, 5
    /// entitlements, 7 DER entitlements); `None` when the CodeDirectory has no such slot.
    pub fn special_slot(&self, slot: u32) -> Option<&[u8]> {
        if slot == 0 || slot > self.special_slots {
            return None;
        }
        let size = usize::from(self.hash_size);
        let start = self.hash_offset.checked_sub(slot as usize * size)?;
        self.blob.get(start..start + size)
    }

    /// Whether `bytes` hash to special slot `slot`. `None` when there is no such slot or the
    /// hash type is unknown. An all-zero slot means "not sealed": `None` too.
    pub fn verify_special(&self, slot: u32, bytes: &[u8]) -> Option<bool> {
        let stored = self.special_slot(slot)?;
        if stored.iter().all(|byte| *byte == 0) {
            return None;
        }
        let digest = hash(self.hash_type, bytes)?;
        Some(digest[..stored.len().min(digest.len())] == *stored)
    }

    /// Recomputes every page hash over `image` (the Mach-O image the signature is in). An
    /// encrypted image (App Store FairPlay) does not match: its pages were hashed before
    /// encryption.
    pub fn verify_pages(&self, image: &[u8]) -> PageVerification {
        let mut result = PageVerification {
            checked: 0,
            mismatched: Vec::new(),
            problem: None,
        };
        if hash(self.hash_type, b"").is_none() {
            result.problem = Some("unknown hash type");
            return result;
        }
        let Ok(limit) = usize::try_from(self.code_limit) else {
            result.problem = Some("code limit past the image");
            return result;
        };
        if limit > image.len() {
            result.problem = Some("code limit past the image");
            return result;
        }
        let page = if self.page_size_log2 == 0 {
            limit.max(1)
        } else {
            1usize << self.page_size_log2
        };
        let size = usize::from(self.hash_size);
        let needed = limit.div_ceil(page);
        if needed != self.code_slots as usize {
            result.problem = Some("code slot count does not match the code limit");
            return result;
        }
        for index in 0..needed {
            let start = index * page;
            let end = (start + page).min(limit);
            let digest = hash(self.hash_type, &image[start..end]).expect("known hash type");
            let stored = &self.blob[self.hash_offset + index * size..][..size];
            if digest[..size.min(digest.len())] != *stored && result.mismatched.len() < 32 {
                result.mismatched.push(index);
            }
            result.checked += 1;
        }
        result
    }
}

/// Reads the signature data `LC_CODE_SIGNATURE` points to.
pub fn parse(data: &[u8]) -> Result<CodeSignature, SignatureError> {
    if read_u32_be(data, 0) != Some(SUPERBLOB) {
        return Err(SignatureError::NotSuperBlob);
    }
    let length = read_u32_be(data, 4).ok_or(SignatureError::Truncated)? as usize;
    let count = read_u32_be(data, 8).ok_or(SignatureError::Truncated)? as usize;
    if length > data.len() || length < 12 {
        return Err(SignatureError::Truncated);
    }
    let data = &data[..length];
    let mut signature = CodeSignature {
        code_directories: Vec::new(),
        requirements: None,
        entitlements: None,
        der_entitlements: None,
        cms: None,
        anomalies: Vec::new(),
    };
    let fitting = (length - 12) / 8;
    if count > fitting.min(MAX_BLOBS) {
        signature.anomalies.push(SignatureAnomaly::TooManyBlobs);
    }
    let mut seen: Vec<u32> = Vec::new();
    for index in 0..count.min(fitting).min(MAX_BLOBS) {
        let slot = read_u32_be(data, 12 + index * 8).expect("inside the index");
        let offset = read_u32_be(data, 16 + index * 8).expect("inside the index") as usize;
        if seen.contains(&slot) {
            signature
                .anomalies
                .push(SignatureAnomaly::DuplicateSlot { slot });
            continue;
        }
        seen.push(slot);
        let Some(blob) = blob_at(data, offset) else {
            signature
                .anomalies
                .push(SignatureAnomaly::BlobOutOfBounds { slot });
            continue;
        };
        let magic = read_u32_be(blob, 0).expect("blob header");
        let expected = match slot {
            SLOT_CODE_DIRECTORY | SLOT_ALTERNATE_FIRST..=SLOT_ALTERNATE_LAST => CODE_DIRECTORY,
            SLOT_REQUIREMENTS => REQUIREMENTS,
            SLOT_ENTITLEMENTS => ENTITLEMENTS,
            SLOT_DER_ENTITLEMENTS => DER_ENTITLEMENTS,
            SLOT_CMS => BLOB_WRAPPER,
            // Launch constraints and other slots: kept out of the model, not an anomaly.
            _ => continue,
        };
        if magic != expected {
            signature
                .anomalies
                .push(SignatureAnomaly::UnexpectedMagic { slot, magic });
            continue;
        }
        match slot {
            SLOT_REQUIREMENTS => signature.requirements = Some(blob.to_vec()),
            SLOT_ENTITLEMENTS => {
                signature.entitlements = Some(Entitlements {
                    blob: blob.to_vec(),
                    plist: plist::parse(&blob[8..]),
                });
            }
            SLOT_DER_ENTITLEMENTS => signature.der_entitlements = Some(blob.to_vec()),
            SLOT_CMS => signature.cms = Some(blob[8..].to_vec()),
            _ => match code_directory(slot, blob) {
                Ok(directory) => signature.code_directories.push(directory),
                Err(reason) => signature
                    .anomalies
                    .push(SignatureAnomaly::InvalidCodeDirectory { slot, reason }),
            },
        }
    }
    // A signature without a readable CodeDirectory is kept, with its anomalies: it signs
    // nothing ([`CodeSignature::best_code_directory`] is `None`).
    // Slot 0 first, then the alternates in slot order.
    signature
        .code_directories
        .sort_by_key(|directory| directory.slot);
    Ok(signature)
}

/// The blob at `offset`: its 8-byte header (magic, length) and the length it declares, all
/// inside `data`.
fn blob_at(data: &[u8], offset: usize) -> Option<&[u8]> {
    let length = read_u32_be(data, offset.checked_add(4)?)? as usize;
    if length < 8 {
        return None;
    }
    data.get(offset..offset.checked_add(length)?)
}

fn code_directory(slot: u32, blob: &[u8]) -> Result<CodeDirectory, &'static str> {
    let word = |offset: usize| read_u32_be(blob, offset).ok_or("shorter than its fields");
    let byte = |offset: usize| blob.get(offset).copied().ok_or("shorter than its fields");
    let version = word(8)?;
    let flags = word(12)?;
    let hash_offset = word(16)? as usize;
    let identifier_offset = word(20)? as usize;
    let special_slots = word(24)?;
    let code_slots = word(28)?;
    let code_limit32 = word(32)?;
    let hash_size = byte(36)?;
    let hash_type = byte(37)?;
    let platform = byte(38)?;
    let page_size_log2 = byte(39)?;
    if code_slots > MAX_CODE_SLOTS || special_slots > 64 {
        return Err("more slots than an image can have");
    }
    if page_size_log2 > 30 {
        return Err("page size too large");
    }
    let size = usize::from(hash_size);
    let hashes_start = hash_offset
        .checked_sub(special_slots as usize * size)
        .ok_or("special slots before the CodeDirectory's start")?;
    let hashes_end = hash_offset
        .checked_add(code_slots as usize * size)
        .ok_or("hash table too large")?;
    if hashes_start < 44 || hashes_end > blob.len() {
        return Err("hash table outside the CodeDirectory");
    }
    let identifier =
        c_string(blob, identifier_offset).ok_or("identifier outside the CodeDirectory")?;
    let team_id = if version >= 0x20200 {
        match word(48)? {
            0 => None,
            offset => Some(c_string(blob, offset as usize).ok_or("team identifier outside")?),
        }
    } else {
        None
    };
    let code_limit = if version >= 0x20300 {
        match read_u32_be(blob, 56).zip(read_u32_be(blob, 60)) {
            Some((high, low)) if high != 0 || low != 0 => (u64::from(high) << 32) | u64::from(low),
            _ => u64::from(code_limit32),
        }
    } else {
        u64::from(code_limit32)
    };
    let exec_segment_flags = (version >= 0x20400)
        .then(|| read_u32_be(blob, 80).zip(read_u32_be(blob, 84)))
        .flatten()
        .map(|(high, low)| (u64::from(high) << 32) | u64::from(low));
    let runtime = (version >= 0x20500)
        .then(|| read_u32_be(blob, 88))
        .flatten();
    Ok(CodeDirectory {
        slot,
        version,
        flags,
        hash_type,
        hash_size,
        page_size_log2,
        special_slots,
        code_slots,
        code_limit,
        identifier,
        team_id,
        platform,
        exec_segment_flags,
        runtime,
        blob: blob.to_vec(),
        hash_offset,
    })
}

/// A NUL-terminated string at `offset` inside `blob`.
fn c_string(blob: &[u8], offset: usize) -> Option<String> {
    let rest = blob.get(offset..)?;
    let end = rest.iter().position(|byte| *byte == 0)?;
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// The digest of a CodeDirectory hash type.
fn hash(hash_type: u8, bytes: &[u8]) -> Option<Vec<u8>> {
    Some(match hash_type {
        1 => Sha1::digest(bytes).to_vec(),
        2 | 3 => Sha256::digest(bytes).to_vec(),
        4 => Sha384::digest(bytes).to_vec(),
        _ => return None,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
