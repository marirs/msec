//! The string table: `string_id_item` offsets to `string_data_item`s, each a ULEB128 length in
//! UTF-16 code units followed by MUTF-8 and a zero byte.
//!
//! Decoding follows ART's `CheckStringDataItem`, so a string msec reads is one ART accepts.
//! Strings are kept in one buffer, so the memory a file can claim is bounded by the bytes
//! decoded, and decoding is bounded by a budget (see [`StringTable::read`]).

use std::cmp::Ordering;

use super::{Anomalies, DexAnomalyKind};
use crate::android::chunk::u32_at;

/// Marks a string that was not read (invalid, or past the decoding budget).
const UNREAD: u32 = u32::MAX;

/// Every string of one DEX file, decoded to UTF-8.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct StringTable {
    /// All decoded strings, back to back.
    text: String,
    /// `(start, length)` of each string in `text`; `start` is [`UNREAD`] for a string that
    /// could not be read.
    spans: Vec<(u32, u32)>,
}

impl StringTable {
    /// Reads `count` string IDs at `ids_offset`. The IDs were bounds-checked by the caller; the
    /// data each points to is checked here, within `bytes[lower..upper]`.
    ///
    /// `budget` caps the bytes decoded, and is shared by every logical file of a container
    /// (see [`Budgets`](super::Budgets)). Strings past it are left unread and reported as
    /// [`DexAnomalyKind::StringBudgetExhausted`].
    pub(super) fn read(
        bytes: &[u8],
        ids_offset: usize,
        count: u32,
        bounds: (usize, usize),
        budget: &mut usize,
        anomalies: &mut Anomalies,
    ) -> Self {
        let mut table = Self {
            text: String::new(),
            spans: Vec::with_capacity(count as usize),
        };
        let mut units: Vec<u16> = Vec::new();
        let mut previous: Option<Vec<u16>> = None;
        for index in 0..count {
            let data_offset = u32_at(bytes, ids_offset + 4 * index as usize)
                .expect("the string_ids table was bounds-checked")
                as usize;
            units.clear();
            match decode(bytes, data_offset, bounds, budget, &mut units) {
                Ok(()) => {}
                Err(StringProblem::BudgetExhausted) => {
                    anomalies.record(DexAnomalyKind::StringBudgetExhausted {
                        first_unread: index,
                    });
                    table.spans.resize(count as usize, (UNREAD, 0));
                    return table;
                }
                Err(StringProblem::Invalid) => {
                    anomalies.record(DexAnomalyKind::InvalidString { index });
                    table.spans.push((UNREAD, 0));
                    previous = None;
                    continue;
                }
            }
            // ART requires string_ids sorted by UTF-16 code unit, without duplicates.
            if let Some(previous) = &previous
                && previous.as_slice().cmp(units.as_slice()) != Ordering::Less
            {
                anomalies.record(DexAnomalyKind::StringsOutOfOrder { index });
            }
            table.push(&units);
            previous = Some(std::mem::take(&mut units));
        }
        table
    }

    fn push(&mut self, units: &[u16]) {
        let start = self.text.len();
        // Unpaired surrogates are valid in DEX strings but have no UTF-8 form.
        self.text.extend(
            char::decode_utf16(units.iter().copied())
                .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER)),
        );
        self.spans
            .push((start as u32, (self.text.len() - start) as u32));
    }

    /// The string at `index`; `None` when out of range or not read.
    pub(super) fn get(&self, index: u32) -> Option<&str> {
        let &(start, length) = self.spans.get(index as usize)?;
        if start == UNREAD {
            return None;
        }
        self.text
            .get(start as usize..start as usize + length as usize)
    }

    /// Number of string IDs.
    pub(super) fn len(&self) -> usize {
        self.spans.len()
    }

    /// Strings read, in ID order; `None` for one not read.
    pub(super) fn iter(&self) -> impl Iterator<Item = Option<&str>> {
        (0..self.spans.len() as u32).map(|index| self.get(index))
    }
}

enum StringProblem {
    /// Out of bounds, a bad length, or bytes ART rejects.
    Invalid,
    /// The decoding budget ran out.
    BudgetExhausted,
}

/// Decodes one `string_data_item` into UTF-16 code units, charging each byte to `budget`.
fn decode(
    bytes: &[u8],
    offset: usize,
    (lower, upper): (usize, usize),
    budget: &mut usize,
    units: &mut Vec<u16>,
) -> Result<(), StringProblem> {
    if offset < lower || offset >= upper {
        return Err(StringProblem::Invalid);
    }
    let mut reader = ByteReader {
        bytes: &bytes[..upper],
        position: offset,
        budget,
    };
    let length = reader.uleb128()?;
    for _ in 0..length {
        let first = reader.byte()?;
        let unit = match first >> 4 {
            // A zero byte before `length` units: the string is shorter than declared.
            0x0 if first == 0 => return Err(StringProblem::Invalid),
            0x0..=0x7 => u16::from(first),
            0xc | 0xd => {
                let second = reader.continuation()?;
                let value = (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f);
                // Only U+0000 may use a longer form than it needs (C0 80).
                if value != 0 && value < 0x80 {
                    return Err(StringProblem::Invalid);
                }
                value
            }
            0xe => {
                let second = reader.continuation()?;
                let third = reader.continuation()?;
                let value = (u16::from(first & 0x0f) << 12)
                    | (u16::from(second & 0x3f) << 6)
                    | u16::from(third & 0x3f);
                if value < 0x800 {
                    return Err(StringProblem::Invalid);
                }
                value
            }
            // Continuation bytes, and the four-byte forms of standard UTF-8, which MUTF-8 does
            // not use (it encodes the two surrogates separately).
            _ => return Err(StringProblem::Invalid),
        };
        units.push(unit);
    }
    if reader.byte()? != 0 {
        return Err(StringProblem::Invalid);
    }
    Ok(())
}

struct ByteReader<'data, 'budget> {
    bytes: &'data [u8],
    position: usize,
    budget: &'budget mut usize,
}

impl ByteReader<'_, '_> {
    fn byte(&mut self) -> Result<u8, StringProblem> {
        if *self.budget == 0 {
            return Err(StringProblem::BudgetExhausted);
        }
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(StringProblem::Invalid)?;
        self.position += 1;
        *self.budget -= 1;
        Ok(byte)
    }

    fn continuation(&mut self) -> Result<u8, StringProblem> {
        let byte = self.byte()?;
        if byte & 0xc0 != 0x80 {
            return Err(StringProblem::Invalid);
        }
        Ok(byte)
    }

    /// An unsigned LEB128 of at most five bytes, as ART reads it.
    fn uleb128(&mut self) -> Result<u32, StringProblem> {
        let mut value: u32 = 0;
        for shift in [0, 7, 14, 21, 28] {
            let byte = self.byte()?;
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(StringProblem::Invalid)
    }
}
