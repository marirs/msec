//! The APK content digest of signature schemes v2/v3: the file without the signing block, in
//! three sections (entries, central directory, end record with its central directory offset
//! pointing at where the signing block starts), each split into 1 MiB chunks:
//! `H(0x5a || u32 chunk_count || H(0xa5 || u32 chunk_length || chunk)...)`.

use std::io::{Read, Seek};

use sha2::{Digest, Sha256, Sha512};

use super::crypto::ContentDigest;
use crate::archive::{ArchiveError, ZipArchive};

const CHUNK_LENGTH: u64 = 1024 * 1024;
const CHUNK_PREFIX: u8 = 0xa5;
const TOP_PREFIX: u8 = 0x5a;
/// Offset of the central directory offset field in the end of central directory record.
const END_RECORD_DIRECTORY_OFFSET_FIELD: usize = 16;

/// Why the content digest cannot be computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestProblem {
    /// The archive has no signing block where the schemes need it.
    NoSigningBlock,
    /// ZIP64 or prepended data: the layout signature schemes define does not apply.
    UnsupportedLayout,
    /// Reading the file failed.
    Read(String),
}

/// The chunked SHA-256 and SHA-512 content digests, as requested.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentDigests {
    /// Chunked SHA-256.
    pub sha256: Option<Vec<u8>>,
    /// Chunked SHA-512.
    pub sha512: Option<Vec<u8>>,
}

impl ContentDigests {
    /// The digest for a content digest kind; `None` for verity (not computed).
    pub fn get(&self, kind: ContentDigest) -> Option<&[u8]> {
        match kind {
            ContentDigest::ChunkedSha256 => self.sha256.as_deref(),
            ContentDigest::ChunkedSha512 => self.sha512.as_deref(),
            ContentDigest::VeritySha256 => None,
        }
    }
}

/// Computes the requested chunked digests in one pass over the file.
pub fn content_digests<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    want_sha256: bool,
    want_sha512: bool,
) -> Result<ContentDigests, DigestProblem> {
    let layout = archive.layout().clone();
    let block = layout
        .apk_signing_block
        .clone()
        .ok_or(DigestProblem::NoSigningBlock)?;
    if layout.zip64 || layout.shift > 0 {
        return Err(DigestProblem::UnsupportedLayout);
    }
    let read_error = |error: ArchiveError| DigestProblem::Read(error.to_string());
    let mut end_record = archive
        .read_raw(
            layout.end_record_offset,
            layout.archive_bytes - layout.end_record_offset,
        )
        .map_err(read_error)?;
    let block_start = u32::try_from(block.start).map_err(|_| DigestProblem::UnsupportedLayout)?;
    end_record
        .get_mut(END_RECORD_DIRECTORY_OFFSET_FIELD..END_RECORD_DIRECTORY_OFFSET_FIELD + 4)
        .ok_or(DigestProblem::UnsupportedLayout)?
        .copy_from_slice(&block_start.to_le_bytes());

    let mut state = ChunkState::new(want_sha256, want_sha512);
    for (start, length) in [
        (0, block.start),
        (
            layout.central_directory_offset,
            layout.central_directory_size,
        ),
    ] {
        let mut offset = start;
        while offset < start + length {
            let chunk_length = CHUNK_LENGTH.min(start + length - offset);
            let chunk = archive.read_raw(offset, chunk_length).map_err(read_error)?;
            state.add(&chunk);
            offset += chunk_length;
        }
    }
    for chunk in end_record.chunks(CHUNK_LENGTH as usize) {
        state.add(chunk);
    }
    Ok(state.finish())
}

/// Per-chunk digests collected so far, per hash.
struct ChunkState {
    sha256: Option<Vec<u8>>,
    sha512: Option<Vec<u8>>,
    chunks: u32,
}

impl ChunkState {
    fn new(sha256: bool, sha512: bool) -> Self {
        Self {
            sha256: sha256.then(Vec::new),
            sha512: sha512.then(Vec::new),
            chunks: 0,
        }
    }

    fn add(&mut self, chunk: &[u8]) {
        let length = (chunk.len() as u32).to_le_bytes();
        if let Some(digests) = &mut self.sha256 {
            digests.extend_from_slice(
                &Sha256::new()
                    .chain_update([CHUNK_PREFIX])
                    .chain_update(length)
                    .chain_update(chunk)
                    .finalize(),
            );
        }
        if let Some(digests) = &mut self.sha512 {
            digests.extend_from_slice(
                &Sha512::new()
                    .chain_update([CHUNK_PREFIX])
                    .chain_update(length)
                    .chain_update(chunk)
                    .finalize(),
            );
        }
        self.chunks += 1;
    }

    fn finish(self) -> ContentDigests {
        let count = self.chunks.to_le_bytes();
        ContentDigests {
            sha256: self.sha256.map(|digests| {
                Sha256::new()
                    .chain_update([TOP_PREFIX])
                    .chain_update(count)
                    .chain_update(&digests)
                    .finalize()
                    .to_vec()
            }),
            sha512: self.sha512.map(|digests| {
                Sha512::new()
                    .chain_update([TOP_PREFIX])
                    .chain_update(count)
                    .chain_update(&digests)
                    .finalize()
                    .to_vec()
            }),
        }
    }
}
