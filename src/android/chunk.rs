//! Chunk framing shared by binary XML and the resource table, as defined in AOSP
//! `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`.
//!
//! Every chunk starts with `ResChunk_header { u16 type; u16 headerSize; u32 size; }`. All reads
//! are bounds-checked; nothing here panics on hostile input.

pub(crate) const RES_STRING_POOL_TYPE: u16 = 0x0001;
pub(crate) const RES_TABLE_TYPE: u16 = 0x0002;
pub(crate) const RES_XML_TYPE: u16 = 0x0003;
pub(crate) const RES_XML_FIRST_CHUNK_TYPE: u16 = 0x0100;
pub(crate) const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
pub(crate) const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
pub(crate) const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
pub(crate) const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
pub(crate) const RES_XML_CDATA_TYPE: u16 = 0x0104;
pub(crate) const RES_XML_LAST_CHUNK_TYPE: u16 = 0x017f;
pub(crate) const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
pub(crate) const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
pub(crate) const RES_TABLE_TYPE_TYPE: u16 = 0x0201;

pub(crate) const CHUNK_HEADER_LENGTH: usize = 8;

/// Little-endian `u16` at `offset`, or `None` past the end.
pub(crate) fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Little-endian `u32` at `offset`, or `None` past the end.
pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Why a chunk header cannot be used. Android's `validate_chunk` rejects each of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkProblem {
    /// Fewer than eight bytes remain for the header.
    Truncated,
    /// The declared header size is smaller than this chunk type needs.
    HeaderTooSmall,
    /// The declared chunk size is smaller than its header.
    SizeSmallerThanHeader,
    /// The chunk extends past the end of its container.
    ExtendsPastEnd,
}

/// One chunk, borrowed from the buffer it was read from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Chunk<'data> {
    pub(crate) kind: u16,
    pub(crate) header_size: usize,
    /// Position of the chunk in the buffer.
    pub(crate) offset: usize,
    /// The whole chunk, header included.
    pub(crate) bytes: &'data [u8],
}

impl<'data> Chunk<'data> {
    /// Reads the chunk at `offset`, which must end at or before `end`. `min_header` is the
    /// smallest header Android accepts in this position.
    pub(crate) fn read(
        buffer: &'data [u8],
        offset: usize,
        end: usize,
        min_header: usize,
    ) -> Result<Self, ChunkProblem> {
        let end = end.min(buffer.len());
        let kind = u16_at(buffer, offset).ok_or(ChunkProblem::Truncated)?;
        let header_size = usize::from(u16_at(buffer, offset + 2).ok_or(ChunkProblem::Truncated)?);
        let size = u32_at(buffer, offset + 4).ok_or(ChunkProblem::Truncated)? as usize;
        if offset + CHUNK_HEADER_LENGTH > end {
            return Err(ChunkProblem::Truncated);
        }
        if header_size < min_header.max(CHUNK_HEADER_LENGTH) {
            return Err(ChunkProblem::HeaderTooSmall);
        }
        if size < header_size {
            return Err(ChunkProblem::SizeSmallerThanHeader);
        }
        let chunk_end = offset
            .checked_add(size)
            .ok_or(ChunkProblem::ExtendsPastEnd)?;
        if chunk_end > end {
            return Err(ChunkProblem::ExtendsPastEnd);
        }
        Ok(Self {
            kind,
            header_size,
            offset,
            bytes: &buffer[offset..chunk_end],
        })
    }

    /// Android also requires both sizes to be multiples of four.
    pub(crate) fn is_aligned(&self) -> bool {
        (self.header_size | self.bytes.len()) & 0x3 == 0
    }

    pub(crate) fn end(&self) -> usize {
        self.offset + self.bytes.len()
    }

    pub(crate) fn u16_at(&self, offset: usize) -> Option<u16> {
        u16_at(self.bytes, offset)
    }

    pub(crate) fn u32_at(&self, offset: usize) -> Option<u32> {
        u32_at(self.bytes, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u16, header_size: u16, size: u32) -> Vec<u8> {
        let mut bytes = kind.to_le_bytes().to_vec();
        bytes.extend_from_slice(&header_size.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn rejects_every_inconsistent_header() {
        let mut ok = header(3, 8, 12);
        ok.extend_from_slice(&[0; 4]);
        assert!(Chunk::read(&ok, 0, ok.len(), 8).is_ok());
        assert_eq!(
            Chunk::read(&ok[..6], 0, 6, 8).unwrap_err(),
            ChunkProblem::Truncated
        );
        assert_eq!(
            Chunk::read(&header(3, 4, 8), 0, 8, 8).unwrap_err(),
            ChunkProblem::HeaderTooSmall
        );
        assert_eq!(
            Chunk::read(&header(3, 16, 8), 0, 8, 8).unwrap_err(),
            ChunkProblem::SizeSmallerThanHeader
        );
        assert_eq!(
            Chunk::read(&header(3, 8, 64), 0, 8, 8).unwrap_err(),
            ChunkProblem::ExtendsPastEnd
        );
        assert_eq!(
            Chunk::read(&header(3, 8, u32::MAX), 0, 8, 8).unwrap_err(),
            ChunkProblem::ExtendsPastEnd
        );
        assert!(
            !Chunk::read(&[header(3, 8, 10), vec![0; 2]].concat(), 0, 10, 8)
                .unwrap()
                .is_aligned()
        );
    }
}
