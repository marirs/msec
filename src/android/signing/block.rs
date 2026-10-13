//! The APK Signing Block: `u64 size, (u64 length, u32 id, value)*, u64 size, "APK Sig Block 42"`.

/// APK Signature Scheme v2.
pub const V2_BLOCK_ID: u32 = 0x7109_871a;
/// APK Signature Scheme v3.
pub const V3_BLOCK_ID: u32 = 0xf053_68c0;
/// APK Signature Scheme v3.1 (rotation targeting Android 13 and later).
pub const V31_BLOCK_ID: u32 = 0x1b93_ad61;
/// Padding so the block size is a multiple of 4 KiB (for fs-verity).
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x4272_6577;
/// Source stamp v1 (which tool or store produced the APK).
pub const SOURCE_STAMP_V1_BLOCK_ID: u32 = 0x2b09_189e;
/// Source stamp v2.
pub const SOURCE_STAMP_V2_BLOCK_ID: u32 = 0x6dff_800d;
/// Dependency metadata the Android Gradle plugin embeds, encrypted for Google Play.
pub const DEPENDENCY_INFO_BLOCK_ID: u32 = 0x504b_4453;
/// Google Play's frosting (added when Play delivers the APK).
pub const PLAY_FROSTING_BLOCK_ID: u32 = 0x2146_444e;

/// Footer: `u64 size` then the 16-byte magic.
const FOOTER_LENGTH: usize = 24;
/// Leading `u64 size`.
const HEADER_LENGTH: usize = 8;

/// What a signing block entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockKind {
    /// v2 signatures.
    SchemeV2,
    /// v3 signatures.
    SchemeV3,
    /// v3.1 signatures.
    SchemeV31,
    /// Verity padding.
    VerityPadding,
    /// Source stamp.
    SourceStamp,
    /// Android Gradle plugin dependency metadata.
    DependencyInfo,
    /// Google Play frosting.
    PlayFrosting,
    /// Anything else, by ID.
    Other(u32),
}

impl BlockKind {
    /// The kind of an entry ID.
    pub fn from_id(id: u32) -> Self {
        match id {
            V2_BLOCK_ID => Self::SchemeV2,
            V3_BLOCK_ID => Self::SchemeV3,
            V31_BLOCK_ID => Self::SchemeV31,
            VERITY_PADDING_BLOCK_ID => Self::VerityPadding,
            SOURCE_STAMP_V1_BLOCK_ID | SOURCE_STAMP_V2_BLOCK_ID => Self::SourceStamp,
            DEPENDENCY_INFO_BLOCK_ID => Self::DependencyInfo,
            PLAY_FROSTING_BLOCK_ID => Self::PlayFrosting,
            other => Self::Other(other),
        }
    }

    /// Human-readable name.
    pub fn label(self) -> String {
        match self {
            Self::SchemeV2 => "APK Signature Scheme v2".to_owned(),
            Self::SchemeV3 => "APK Signature Scheme v3".to_owned(),
            Self::SchemeV31 => "APK Signature Scheme v3.1".to_owned(),
            Self::VerityPadding => "verity padding".to_owned(),
            Self::SourceStamp => "source stamp".to_owned(),
            Self::DependencyInfo => "dependency metadata (Android Gradle plugin)".to_owned(),
            Self::PlayFrosting => "Google Play frosting".to_owned(),
            Self::Other(id) => format!("unknown block 0x{id:08x}"),
        }
    }
}

/// One `(id, value)` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    /// The entry ID.
    pub id: u32,
    /// The value.
    pub value: Vec<u8>,
}

/// Why the signing block cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockProblem {
    /// The two size fields disagree, or the block is too short.
    InconsistentSize,
    /// An entry's length runs past the block.
    EntryOutOfBounds,
}

/// Parses the entries of a signing block (the whole block, header to magic).
pub fn parse(block: &[u8]) -> Result<Vec<BlockEntry>, BlockProblem> {
    if block.len() < HEADER_LENGTH + FOOTER_LENGTH {
        return Err(BlockProblem::InconsistentSize);
    }
    let leading = u64_at(block, 0);
    let trailing = u64_at(block, block.len() - FOOTER_LENGTH);
    if leading != trailing || leading != (block.len() - HEADER_LENGTH) as u64 {
        return Err(BlockProblem::InconsistentSize);
    }
    let pairs = &block[HEADER_LENGTH..block.len() - FOOTER_LENGTH];
    let mut entries = Vec::new();
    let mut position = 0;
    while position < pairs.len() {
        let length = pairs
            .get(position..position + 8)
            .map(|bytes| u64_at(bytes, 0))
            .ok_or(BlockProblem::EntryOutOfBounds)?;
        let start = position + 8;
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| start.checked_add(length))
            .filter(|&end| length >= 4 && end <= pairs.len())
            .ok_or(BlockProblem::EntryOutOfBounds)?;
        let id = u32::from_le_bytes(pairs[start..start + 4].try_into().expect("4 bytes"));
        entries.push(BlockEntry {
            id,
            value: pairs[start + 4..end].to_vec(),
        });
        position = end;
    }
    Ok(entries)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("caller checked length"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(entries: &[(u32, &[u8])]) -> Vec<u8> {
        let mut pairs = Vec::new();
        for (id, value) in entries {
            pairs.extend_from_slice(&((value.len() + 4) as u64).to_le_bytes());
            pairs.extend_from_slice(&id.to_le_bytes());
            pairs.extend_from_slice(value);
        }
        let size = (pairs.len() + FOOTER_LENGTH) as u64;
        [
            size.to_le_bytes().as_slice(),
            &pairs,
            &size.to_le_bytes(),
            b"APK Sig Block 42",
        ]
        .concat()
    }

    #[test]
    fn parses_entries_and_rejects_bad_sizes() {
        let bytes = block(&[(V2_BLOCK_ID, b"v2"), (PLAY_FROSTING_BLOCK_ID, b"")]);
        let entries = parse(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(BlockKind::from_id(entries[1].id), BlockKind::PlayFrosting);
        let mut broken = bytes.clone();
        broken[8] = 0xff;
        assert_eq!(parse(&broken).unwrap_err(), BlockProblem::EntryOutOfBounds);
        let mut mismatched = bytes;
        mismatched[0] ^= 1;
        assert_eq!(
            parse(&mismatched).unwrap_err(),
            BlockProblem::InconsistentSize
        );
    }
}
