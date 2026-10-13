//! ZIP record layouts (APPNOTE 6.3.10) parsed from untrusted bytes.
//!
//! Every read is bounds-checked through [`ByteReader`]; malformed input yields `None` or a
//! typed error, never a panic. Only the fields msec uses are kept.

/// End of central directory record signature (`PK\x05\x06`).
pub(super) const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
/// ZIP64 end of central directory locator signature (`PK\x06\x07`).
pub(super) const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
/// ZIP64 end of central directory record signature (`PK\x06\x06`).
pub(super) const ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0606_4b50;
/// Central directory file header signature (`PK\x01\x02`).
pub(super) const CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
/// Local file header signature (`PK\x03\x04`).
pub(super) const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;
/// Optional signature that starts a data descriptor (`PK\x07\x08`).
pub(super) const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
/// Magic that ends an APK Signing Block, which sits directly before the central directory.
pub(super) const APK_SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Compression method 0: data stored as is.
pub(super) const METHOD_STORED: u16 = 0;
/// Compression method 8: raw deflate. The only other method Android can read.
pub(super) const METHOD_DEFLATE: u16 = 8;

pub(super) const END_OF_CENTRAL_DIRECTORY_LENGTH: usize = 22;
pub(super) const ZIP64_LOCATOR_LENGTH: usize = 20;
pub(super) const ZIP64_END_OF_CENTRAL_DIRECTORY_MIN_LENGTH: usize = 56;
pub(super) const CENTRAL_DIRECTORY_HEADER_LENGTH: usize = 46;
pub(super) const LOCAL_FILE_HEADER_LENGTH: usize = 30;
/// The archive comment is at most 65,535 bytes, so the end record sits within this many bytes
/// of the end of the file.
pub(super) const MAX_END_RECORD_SEARCH: usize = END_OF_CENTRAL_DIRECTORY_LENGTH + u16::MAX as usize;

/// General purpose flag bit 0: entry claims to be encrypted.
pub(super) const FLAG_ENCRYPTED: u16 = 0x0001;
/// General purpose flag bit 3: sizes and CRC follow the data in a data descriptor.
pub(super) const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

const ZIP64_EXTRA_FIELD_ID: u16 = 0x0001;
const U32_SENTINEL: u32 = u32::MAX;
const U16_SENTINEL: u16 = u16::MAX;

/// Little-endian reader over a byte slice that returns `None` instead of reading past the end.
pub(super) struct ByteReader<'bytes> {
    bytes: &'bytes [u8],
    position: usize,
}

impl<'bytes> ByteReader<'bytes> {
    pub(super) fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(super) fn take(&mut self, length: usize) -> Option<&'bytes [u8]> {
        let end = self.position.checked_add(length)?;
        let slice = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    pub(super) fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    pub(super) fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(super) fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    pub(super) fn skip(&mut self, length: usize) -> Option<()> {
        self.take(length).map(|_| ())
    }
}

/// The classic end of central directory record.
#[derive(Debug, Clone, Copy)]
pub(super) struct EndOfCentralDirectory {
    pub(super) total_entries: u16,
    pub(super) central_directory_size: u32,
    pub(super) central_directory_offset: u32,
    pub(super) comment_length: u16,
}

impl EndOfCentralDirectory {
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let mut reader = ByteReader::new(bytes);
        if reader.u32()? != END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            return None;
        }
        reader.skip(4)?; // disk numbers: multi-disk archives are not valid packages
        reader.skip(2)?; // entries on this disk
        Some(Self {
            total_entries: reader.u16()?,
            central_directory_size: reader.u32()?,
            central_directory_offset: reader.u32()?,
            comment_length: reader.u16()?,
        })
    }

    /// Any saturated field means the real value lives in the ZIP64 record.
    pub(super) fn needs_zip64(&self) -> bool {
        self.total_entries == U16_SENTINEL
            || self.central_directory_size == U32_SENTINEL
            || self.central_directory_offset == U32_SENTINEL
    }
}

/// Offset of the ZIP64 end record, from the locator that precedes the classic end record.
pub(super) fn parse_zip64_locator(bytes: &[u8]) -> Option<u64> {
    let mut reader = ByteReader::new(bytes);
    if reader.u32()? != ZIP64_LOCATOR_SIGNATURE {
        return None;
    }
    reader.skip(4)?; // disk with the ZIP64 end record
    reader.u64()
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Zip64EndOfCentralDirectory {
    pub(super) total_entries: u64,
    pub(super) central_directory_size: u64,
    pub(super) central_directory_offset: u64,
}

impl Zip64EndOfCentralDirectory {
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let mut reader = ByteReader::new(bytes);
        if reader.u32()? != ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE {
            return None;
        }
        reader.skip(8)?; // size of record
        reader.skip(4)?; // versions
        reader.skip(8)?; // disk numbers
        reader.skip(8)?; // entries on this disk
        Some(Self {
            total_entries: reader.u64()?,
            central_directory_size: reader.u64()?,
            central_directory_offset: reader.u64()?,
        })
    }
}

/// One central directory file header, with ZIP64 values already applied.
#[derive(Debug, Clone)]
pub(super) struct CentralDirectoryRecord {
    pub(super) version_made_by: u16,
    pub(super) flags: u16,
    pub(super) method: u16,
    pub(super) crc32: u32,
    pub(super) compressed_size: u64,
    pub(super) uncompressed_size: u64,
    pub(super) external_attributes: u32,
    pub(super) local_header_offset: u64,
    pub(super) raw_name: Vec<u8>,
    /// Bytes this record occupies in the central directory.
    pub(super) record_length: usize,
}

impl CentralDirectoryRecord {
    /// Parses the record at the start of `bytes` (the rest of the central directory).
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let mut reader = ByteReader::new(bytes);
        if reader.u32()? != CENTRAL_DIRECTORY_SIGNATURE {
            return None;
        }
        let version_made_by = reader.u16()?;
        reader.skip(2)?; // version needed
        let flags = reader.u16()?;
        let method = reader.u16()?;
        reader.skip(4)?; // modification time and date
        let crc32 = reader.u32()?;
        let compressed_size_32 = reader.u32()?;
        let uncompressed_size_32 = reader.u32()?;
        let name_length = usize::from(reader.u16()?);
        let extra_length = usize::from(reader.u16()?);
        let comment_length = usize::from(reader.u16()?);
        reader.skip(2)?; // disk number start
        reader.skip(2)?; // internal attributes
        let external_attributes = reader.u32()?;
        let local_header_offset_32 = reader.u32()?;
        let raw_name = reader.take(name_length)?.to_vec();
        let extra = reader.take(extra_length)?;
        reader.skip(comment_length)?;

        let zip64 = Zip64ExtraValues::parse(
            extra,
            uncompressed_size_32 == U32_SENTINEL,
            compressed_size_32 == U32_SENTINEL,
            local_header_offset_32 == U32_SENTINEL,
        )?;
        Some(Self {
            version_made_by,
            flags,
            method,
            crc32,
            compressed_size: zip64
                .compressed_size
                .unwrap_or(u64::from(compressed_size_32)),
            uncompressed_size: zip64
                .uncompressed_size
                .unwrap_or(u64::from(uncompressed_size_32)),
            external_attributes,
            local_header_offset: zip64
                .local_header_offset
                .unwrap_or(u64::from(local_header_offset_32)),
            raw_name,
            record_length: CENTRAL_DIRECTORY_HEADER_LENGTH
                + name_length
                + extra_length
                + comment_length,
        })
    }

    /// Unix permission bits, when the archive was made on Unix (APPNOTE 4.4.2.1).
    pub(super) fn unix_mode(&self) -> Option<u32> {
        (self.version_made_by >> 8 == 3).then_some(self.external_attributes >> 16)
    }
}

/// Values from the ZIP64 extended information extra field. A value is present only when the
/// corresponding 32-bit field is saturated, in this fixed order.
#[derive(Default)]
struct Zip64ExtraValues {
    uncompressed_size: Option<u64>,
    compressed_size: Option<u64>,
    local_header_offset: Option<u64>,
}

impl Zip64ExtraValues {
    /// Returns `None` when a saturated field has no ZIP64 value to replace it: the record is
    /// then unusable.
    fn parse(
        extra: &[u8],
        needs_uncompressed: bool,
        needs_compressed: bool,
        needs_offset: bool,
    ) -> Option<Self> {
        if !(needs_uncompressed || needs_compressed || needs_offset) {
            return Some(Self::default());
        }
        let mut fields = ByteReader::new(extra);
        while let (Some(id), Some(length)) = (fields.u16(), fields.u16()) {
            let data = fields.take(usize::from(length))?;
            if id != ZIP64_EXTRA_FIELD_ID {
                continue;
            }
            let mut values = ByteReader::new(data);
            let mut parsed = Self::default();
            if needs_uncompressed {
                parsed.uncompressed_size = Some(values.u64()?);
            }
            if needs_compressed {
                parsed.compressed_size = Some(values.u64()?);
            }
            if needs_offset {
                parsed.local_header_offset = Some(values.u64()?);
            }
            return Some(parsed);
        }
        None
    }
}

/// The fixed part of a local file header plus its name.
#[derive(Debug, Clone)]
pub(super) struct LocalFileHeader {
    pub(super) flags: u16,
    pub(super) method: u16,
    pub(super) crc32: u32,
    pub(super) compressed_size_32: u32,
    pub(super) uncompressed_size_32: u32,
    pub(super) raw_name: Vec<u8>,
    pub(super) extra_length: usize,
}

impl LocalFileHeader {
    /// Parses a header from a buffer that holds at least the fixed part and the name.
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        let mut reader = ByteReader::new(bytes);
        if reader.u32()? != LOCAL_FILE_HEADER_SIGNATURE {
            return None;
        }
        reader.skip(2)?; // version needed
        let flags = reader.u16()?;
        let method = reader.u16()?;
        reader.skip(4)?; // modification time and date
        let crc32 = reader.u32()?;
        let compressed_size_32 = reader.u32()?;
        let uncompressed_size_32 = reader.u32()?;
        let name_length = usize::from(reader.u16()?);
        let extra_length = usize::from(reader.u16()?);
        let raw_name = reader.take(name_length)?.to_vec();
        Some(Self {
            flags,
            method,
            crc32,
            compressed_size_32,
            uncompressed_size_32,
            raw_name,
            extra_length,
        })
    }

    /// Name length declared in a fixed header, read before the name itself is fetched.
    pub(super) fn declared_name_length(fixed_part: &[u8]) -> Option<usize> {
        let mut reader = ByteReader::new(fixed_part);
        reader.skip(26)?;
        reader.u16().map(usize::from)
    }
}

/// True when the 32-bit sizes in a local header are ZIP64 placeholders (the real values are in
/// its extra field, which Android also reads; msec then trusts the central directory sizes).
pub(super) fn local_sizes_are_zip64(header: &LocalFileHeader) -> bool {
    header.compressed_size_32 == U32_SENTINEL || header.uncompressed_size_32 == U32_SENTINEL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_reader_never_reads_past_the_end() {
        let mut reader = ByteReader::new(&[1, 2, 3]);
        assert_eq!(reader.u16(), Some(0x0201));
        assert_eq!(reader.u16(), None);
        assert_eq!(reader.take(usize::MAX), None);
    }

    #[test]
    fn zip64_extra_values_follow_saturated_fields_in_order() {
        // id 0x0001, length 16: uncompressed then compressed.
        let mut extra = vec![0x01, 0x00, 16, 0x00];
        extra.extend_from_slice(&7u64.to_le_bytes());
        extra.extend_from_slice(&5u64.to_le_bytes());
        let parsed = Zip64ExtraValues::parse(&extra, true, true, false).unwrap();
        assert_eq!(parsed.uncompressed_size, Some(7));
        assert_eq!(parsed.compressed_size, Some(5));
        assert_eq!(parsed.local_header_offset, None);
        // A saturated field without a ZIP64 extra field is unusable.
        assert!(Zip64ExtraValues::parse(&[], true, false, false).is_none());
    }
}
