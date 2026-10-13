//! `ResStringPool`: the string table at the start of binary XML files and resource tables.
//!
//! Strings are decoded on demand. Out-of-range indices and lengths yield `None` (Android's
//! `stringAt` returns NULL in the same cases); invalid UTF-8 or UTF-16 is decoded lossily.

use super::chunk::{Chunk, u16_at, u32_at};

/// `ResStringPool_header`: chunk header, string count, style count, flags, strings start,
/// styles start.
const STRING_POOL_HEADER_LENGTH: usize = 28;
const UTF8_FLAG: u32 = 1 << 8;

/// Why a string pool cannot be used at all. Android rejects the containing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringPoolProblem {
    /// The header is shorter than `ResStringPool_header`.
    HeaderTooSmall,
    /// The offset table does not fit in the chunk.
    OffsetsOutOfBounds,
    /// The string data area starts outside the chunk.
    StringsOutOfBounds,
}

/// Positions of one string pool inside a buffer. Holds no borrow, so it can be stored next to
/// the buffer it describes; pass the same buffer to [`StringPool::get`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct StringPool {
    count: usize,
    utf8: bool,
    /// Absolute position of the `u32` offset table.
    offsets_start: usize,
    /// Absolute range of the string data.
    strings_start: usize,
    strings_end: usize,
}

impl StringPool {
    pub(crate) fn parse(chunk: &Chunk<'_>) -> Result<Self, StringPoolProblem> {
        if chunk.header_size < STRING_POOL_HEADER_LENGTH {
            return Err(StringPoolProblem::HeaderTooSmall);
        }
        let read = |offset| {
            chunk
                .u32_at(offset)
                .ok_or(StringPoolProblem::HeaderTooSmall)
        };
        let count = read(8)? as usize;
        let flags = read(16)?;
        let strings_start = read(20)? as usize;
        let styles_start = read(24)? as usize;

        let offsets_end = count
            .checked_mul(4)
            .and_then(|length| length.checked_add(chunk.header_size))
            .ok_or(StringPoolProblem::OffsetsOutOfBounds)?;
        if offsets_end > chunk.bytes.len() {
            return Err(StringPoolProblem::OffsetsOutOfBounds);
        }
        if count > 0 && strings_start >= chunk.bytes.len() {
            return Err(StringPoolProblem::StringsOutOfBounds);
        }
        // String data runs to the style data, or to the end of the chunk.
        let strings_end = if styles_start > strings_start && styles_start <= chunk.bytes.len() {
            styles_start
        } else {
            chunk.bytes.len()
        };
        Ok(Self {
            count,
            utf8: flags & UTF8_FLAG != 0,
            offsets_start: chunk.offset + chunk.header_size,
            strings_start: chunk.offset + strings_start,
            strings_end: chunk.offset + strings_end,
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// The string at `index`, decoded from `buffer` (the buffer the pool was parsed from).
    pub(crate) fn get(&self, buffer: &[u8], index: u32) -> Option<String> {
        let index = index as usize;
        if index >= self.count {
            return None;
        }
        let relative = u32_at(buffer, self.offsets_start + index * 4)? as usize;
        let start = self.strings_start.checked_add(relative)?;
        let data = buffer.get(start..self.strings_end)?;
        if self.utf8 {
            decode_utf8(data)
        } else {
            decode_utf16(data)
        }
    }
}

/// UTF-8 strings carry their UTF-16 length, then their byte length (each one or two bytes),
/// then the bytes.
fn decode_utf8(data: &[u8]) -> Option<String> {
    let (_, utf16_length_size) = utf8_length(data)?;
    let (byte_length, byte_length_size) = utf8_length(data.get(utf16_length_size..)?)?;
    let start = utf16_length_size + byte_length_size;
    let bytes = data.get(start..start.checked_add(byte_length)?)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// A length of one byte, or two when the high bit of the first is set.
fn utf8_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = usize::from(*data.first()?);
    if first & 0x80 == 0 {
        return Some((first, 1));
    }
    let second = usize::from(*data.get(1)?);
    Some((((first & 0x7f) << 8) | second, 2))
}

/// UTF-16 strings carry their length in code units (one or two `u16`s), then the code units.
fn decode_utf16(data: &[u8]) -> Option<String> {
    let first = usize::from(u16_at(data, 0)?);
    let (length, header) = if first & 0x8000 == 0 {
        (first, 2)
    } else {
        (((first & 0x7fff) << 16) | usize::from(u16_at(data, 2)?), 4)
    };
    let end = header + length.checked_mul(2)?;
    let units: Vec<u16> = data
        .get(header..end)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::android::chunk::RES_STRING_POOL_TYPE;

    /// Encodes a string pool chunk, as aapt2 does.
    pub(crate) fn encode(strings: &[&str], utf8: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for string in strings {
            offsets.push(data.len() as u32);
            if utf8 {
                let units = string.encode_utf16().count();
                push_utf8_length(&mut data, units);
                push_utf8_length(&mut data, string.len());
                data.extend_from_slice(string.as_bytes());
                data.push(0);
            } else {
                let units: Vec<u16> = string.encode_utf16().collect();
                if units.len() > 0x7fff {
                    data.extend_from_slice(&((0x8000 | (units.len() >> 16)) as u16).to_le_bytes());
                }
                data.extend_from_slice(&(units.len() as u16).to_le_bytes());
                for unit in units {
                    data.extend_from_slice(&unit.to_le_bytes());
                }
                data.extend_from_slice(&[0, 0]);
            }
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let strings_start = STRING_POOL_HEADER_LENGTH + offsets.len() * 4;
        let size = strings_start + data.len();
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        chunk.extend_from_slice(&(STRING_POOL_HEADER_LENGTH as u16).to_le_bytes());
        chunk.extend_from_slice(&(size as u32).to_le_bytes());
        chunk.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        chunk.extend_from_slice(&(if utf8 { UTF8_FLAG } else { 0 }).to_le_bytes());
        chunk.extend_from_slice(&(strings_start as u32).to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        for offset in offsets {
            chunk.extend_from_slice(&offset.to_le_bytes());
        }
        chunk.extend_from_slice(&data);
        chunk
    }

    fn push_utf8_length(data: &mut Vec<u8>, length: usize) {
        if length > 0x7f {
            data.push(0x80 | (length >> 8) as u8);
        }
        data.push(length as u8);
    }

    fn pool(bytes: &[u8]) -> StringPool {
        StringPool::parse(&Chunk::read(bytes, 0, bytes.len(), 8).unwrap()).unwrap()
    }

    #[test]
    fn decodes_utf8_and_utf16_pools() {
        let long = "x".repeat(300);
        let strings = ["", "android", "名前", long.as_str()];
        for utf8 in [true, false] {
            let bytes = encode(&strings, utf8);
            let pool = pool(&bytes);
            assert_eq!(pool.len(), 4);
            for (index, expected) in strings.iter().enumerate() {
                assert_eq!(
                    pool.get(&bytes, index as u32).as_deref(),
                    Some(*expected),
                    "utf8={utf8}"
                );
            }
            assert_eq!(pool.get(&bytes, 4), None);
        }
    }

    #[test]
    fn lengths_past_the_pool_yield_none() {
        let mut bytes = encode(&["abc"], false);
        let first_string = STRING_POOL_HEADER_LENGTH + 4;
        bytes[first_string..first_string + 2].copy_from_slice(&0x7000u16.to_le_bytes());
        assert_eq!(pool(&bytes).get(&bytes, 0), None);
    }

    #[test]
    fn rejects_offset_tables_larger_than_the_chunk() {
        let mut bytes = encode(&["abc"], true);
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let chunk = Chunk::read(&bytes, 0, bytes.len(), 8).unwrap();
        assert_eq!(
            StringPool::parse(&chunk).unwrap_err(),
            StringPoolProblem::OffsetsOutOfBounds
        );
    }
}
