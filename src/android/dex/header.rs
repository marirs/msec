//! The DEX header (`header_item`), checked the way ART's `DexFileVerifier::CheckHeader` checks
//! it before anything else in the file is read.

use super::DexError;
use crate::android::chunk::u32_at;

/// `ENDIAN_CONSTANT`: the only byte order ART loads.
const ENDIAN_CONSTANT: u32 = 0x1234_5678;
/// `REVERSE_ENDIAN_CONSTANT`: the tag as a byte-swapped file stores it.
const REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;
/// Header size up to version 040.
pub(super) const HEADER_SIZE: u32 = 0x70;
/// Header size from version 041, which adds `container_size` and `header_offset`.
pub(super) const HEADER_SIZE_V41: u32 = 0x78;
/// The versions ART knows (`kDexMagicVersions`). 036 was never used: Dalvik rejected it.
const KNOWN_VERSIONS: [u16; 6] = [35, 37, 38, 39, 40, 41];
/// First version with the container format.
pub(super) const CONTAINER_VERSION: u16 = 41;

/// Count and file offset of one table of fixed-size items (`*_ids_size`, `*_ids_off`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Table {
    /// Number of items.
    pub count: u32,
    /// Offset from the start of the physical file (for a container, of the container).
    pub offset: u32,
}

/// The fields of `header_item` the reader uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Format version: 35, 37, 38, 39, 40 or 41.
    pub version: u16,
    /// Adler-32 of the file after this field, as declared.
    pub checksum: u32,
    /// SHA-1 of the file after this field, as declared.
    pub signature: [u8; 20],
    /// Size of this logical file, header included.
    pub file_size: u32,
    /// 0x70, or 0x78 from version 041.
    pub header_size: u32,
    /// Offset of the `map_list`.
    pub map_offset: u32,
    /// `string_id_item`s (4 bytes each).
    pub string_ids: Table,
    /// `type_id_item`s (4 bytes each).
    pub type_ids: Table,
    /// `proto_id_item`s (12 bytes each).
    pub proto_ids: Table,
    /// `field_id_item`s (8 bytes each).
    pub field_ids: Table,
    /// `method_id_item`s (8 bytes each): the method references, which the 64K limit counts.
    pub method_ids: Table,
    /// `class_def_item`s (32 bytes each).
    pub class_defs: Table,
    /// Size of the whole physical file: `file_size` before version 041.
    pub container_size: u32,
    /// Where this header starts in the physical file: 0 before version 041.
    pub header_offset: u32,
}

impl Header {
    /// Reads and checks the header at `at`. `bytes` is the whole physical file.
    pub(super) fn parse(bytes: &[u8], at: usize) -> Result<Self, DexError> {
        let available = bytes.len().saturating_sub(at);
        let magic = bytes.get(at..at + 8).ok_or(DexError::Truncated {
            length: available as u64,
            needed: u64::from(HEADER_SIZE),
        })?;
        if &magic[..4] == b"cdex" {
            return Err(DexError::CompactDex);
        }
        if &magic[..4] != b"dex\n" {
            return Err(DexError::NotDex);
        }
        let version = parse_version(&magic[4..8])?;
        let expected_header_size = if version >= CONTAINER_VERSION {
            HEADER_SIZE_V41
        } else {
            HEADER_SIZE
        };
        if available < expected_header_size as usize {
            return Err(DexError::Truncated {
                length: available as u64,
                needed: u64::from(expected_header_size),
            });
        }
        let field = |offset: usize| -> u32 {
            u32_at(bytes, at + offset).expect("the header length was checked")
        };
        let table = |offset: usize| Table {
            count: field(offset),
            offset: field(offset + 4),
        };
        match field(40) {
            ENDIAN_CONSTANT => {}
            REVERSE_ENDIAN_CONSTANT => return Err(DexError::ByteSwapped),
            other => return Err(DexError::BadEndianTag(other)),
        }
        let header_size = field(36);
        if header_size != expected_header_size {
            return Err(DexError::BadHeaderSize {
                declared: header_size,
                expected: expected_header_size,
            });
        }
        let file_size = field(32);
        let mut signature = [0; 20];
        signature.copy_from_slice(&bytes[at + 12..at + 32]);
        let (container_size, header_offset) = if version >= CONTAINER_VERSION {
            (field(0x70), field(0x74))
        } else {
            (file_size, 0)
        };
        Ok(Self {
            version,
            checksum: field(8),
            signature,
            file_size,
            header_size,
            map_offset: field(52),
            string_ids: table(56),
            type_ids: table(64),
            proto_ids: table(72),
            field_ids: table(80),
            method_ids: table(88),
            class_defs: table(96),
            container_size,
            header_offset,
        })
    }
}

/// `035\0` to 35. Anything else is a version ART does not load, shown escaped.
fn parse_version(field: &[u8]) -> Result<u16, DexError> {
    let digits = &field[..3];
    let version = (field[3] == 0 && digits.iter().all(u8::is_ascii_digit)).then(|| {
        digits
            .iter()
            .fold(0, |value, digit| value * 10 + u16::from(digit - b'0'))
    });
    match version {
        Some(version) if KNOWN_VERSIONS.contains(&version) => Ok(version),
        _ => Err(DexError::UnsupportedVersion(
            field.escape_ascii().to_string(),
        )),
    }
}
