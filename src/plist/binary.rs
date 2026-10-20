//! The binary format (`bplist00`): a header, objects, an offset table and a 32-byte trailer.
//! Every check below is one Core Foundation makes (`CFBinaryPList.c`), confirmed with `plutil`
//! on the fixtures in `tests/fixtures/plist/binary/`: the trailer's sizes and counts, the
//! offset table ending exactly at the trailer, every object offset inside the object area,
//! each object's bytes inside it, string keys, no cycles, and at most 513 levels of objects.
//!
//! Core Foundation shares an object referenced from several places; msec copies it into each
//! place, within a budget proportional to the input, so a plist built to expand exponentially
//! stops with [`PlistError::ExpansionBudgetExhausted`] instead of exhausting memory. Containers
//! are walked with an explicit stack, not recursion, so the depth Core Foundation allows never
//! depends on the caller's thread stack.

use std::collections::HashSet;

use super::{
    Anomaly, Dictionary, Format, MAX_BINARY_DEPTH, PathSegment, Plist, PlistError, Value, path_text,
};

const HEADER_BYTES: usize = 8;
const TRAILER_BYTES: usize = 32;
/// Values produced per input byte, plus a floor for tiny inputs. An honest plist makes about
/// one value per object reference (each at least a byte); sharing beyond this is refused.
const EXPANSION_PER_BYTE: usize = 4;
const EXPANSION_FLOOR: usize = 1024;

/// Object markers (high nibble).
const MARKER_SIMPLE: u8 = 0x00;
const MARKER_INTEGER: u8 = 0x10;
const MARKER_REAL: u8 = 0x20;
const MARKER_DATE: u8 = 0x33;
const MARKER_DATA: u8 = 0x40;
const MARKER_ASCII: u8 = 0x50;
const MARKER_UTF16: u8 = 0x60;
const MARKER_UID: u8 = 0x80;
const MARKER_ARRAY: u8 = 0xA0;
const MARKER_SET: u8 = 0xC0;
const MARKER_DICTIONARY: u8 = 0xD0;

/// The trailer, as Core Foundation validates it.
struct Trailer {
    offset_size: usize,
    reference_size: usize,
    object_count: usize,
    top_object: usize,
    offset_table: usize,
}

pub(super) fn parse(data: &[u8]) -> Result<Plist, PlistError> {
    // "bplist1x" is a different, newer format; "bplist0" followed by any byte is read as 00.
    match data.get(6) {
        Some(b'0') => {}
        Some(b'1') => return Err(PlistError::Unsupported("binary plist format 1x")),
        _ => return Err(invalid(0, "not a bplist00 header")),
    }
    let trailer = read_trailer(data)?;
    let mut reader = Reader {
        data,
        trailer: &trailer,
        offsets: read_offsets(data, &trailer)?,
        in_progress: HashSet::new(),
        budget: data
            .len()
            .saturating_mul(EXPANSION_PER_BYTE)
            .saturating_add(EXPANSION_FLOOR),
        anomalies: Vec::new(),
    };
    let root = reader.read(trailer.top_object)?;
    Ok(Plist {
        format: Format::Binary,
        root,
        anomalies: reader.anomalies,
    })
}

fn invalid(offset: usize, reason: &'static str) -> PlistError {
    PlistError::InvalidBinary { offset, reason }
}

fn read_trailer(data: &[u8]) -> Result<Trailer, PlistError> {
    if data.len() < HEADER_BYTES + TRAILER_BYTES + 1 {
        return Err(invalid(0, "shorter than a header, an object and a trailer"));
    }
    let at = data.len() - TRAILER_BYTES;
    let bytes = &data[at..];
    let big_endian = |range: std::ops::Range<usize>| {
        bytes[range]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
    };
    let offset_size = usize::from(bytes[6]);
    let reference_size = usize::from(bytes[7]);
    let (object_count, top_object, offset_table) =
        (big_endian(8..16), big_endian(16..24), big_endian(24..32));
    if object_count > i64::MAX as u64 || offset_table > i64::MAX as u64 {
        return Err(invalid(
            at,
            "object count or offset table position out of range",
        ));
    }
    if object_count < 1 {
        return Err(invalid(at, "no objects"));
    }
    if object_count <= top_object {
        return Err(invalid(at, "top object is not one of the objects"));
    }
    if offset_table < (HEADER_BYTES + 1) as u64 {
        return Err(invalid(at, "offset table inside the header"));
    }
    if (at as u64) <= offset_table {
        return Err(invalid(at, "offset table at or after the trailer"));
    }
    if !(1..=8).contains(&offset_size) {
        return Err(invalid(at, "offset size not 1 to 8 bytes"));
    }
    if reference_size < 1 {
        return Err(invalid(at, "object reference size 0"));
    }
    // The offset table ends exactly where the trailer starts: nothing after it, no overlap.
    let table_bytes = object_count
        .checked_mul(offset_size as u64)
        .ok_or_else(|| invalid(at, "offset table size overflows"))?;
    if offset_table.checked_add(table_bytes) != Some(at as u64) {
        return Err(invalid(at, "offset table does not end at the trailer"));
    }
    if reference_size < 8 && (1u64 << (8 * reference_size)) <= object_count {
        return Err(invalid(
            at,
            "object references too small for the object count",
        ));
    }
    if offset_size < 8 && (1u64 << (8 * offset_size)) <= offset_table {
        return Err(invalid(
            at,
            "offsets too small for the offset table position",
        ));
    }
    // Every value now fits in usize: each is below the input length.
    Ok(Trailer {
        offset_size,
        reference_size,
        object_count: object_count as usize,
        top_object: top_object as usize,
        offset_table: offset_table as usize,
    })
}

/// Every object's offset, each checked to lie in the object area (after the header, before
/// the offset table), as Core Foundation checks them all before reading any object.
fn read_offsets(data: &[u8], trailer: &Trailer) -> Result<Vec<usize>, PlistError> {
    let table = &data[trailer.offset_table..data.len() - TRAILER_BYTES];
    let mut offsets = Vec::with_capacity(trailer.object_count);
    for (index, entry) in table.chunks_exact(trailer.offset_size).enumerate() {
        let offset = sized_integer(entry) as usize;
        if !(HEADER_BYTES..trailer.offset_table).contains(&offset) {
            let position = trailer.offset_table + index * trailer.offset_size;
            return Err(invalid(position, "object offset outside the object area"));
        }
        offsets.push(offset);
    }
    Ok(offsets)
}

/// A big-endian unsigned integer of any width, keeping the low 64 bits (as Core Foundation's
/// reader does for references wider than 8 bytes).
fn sized_integer(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

struct Reader<'a> {
    data: &'a [u8],
    trailer: &'a Trailer,
    offsets: Vec<usize>,
    /// Objects being read further up the current chain: meeting one again is a cycle.
    in_progress: HashSet<usize>,
    /// Values still allowed to be produced.
    budget: usize,
    anomalies: Vec<Anomaly>,
}

impl<'a> Reader<'a> {
    /// `length` bytes at `at`, all inside the object area.
    fn bytes(&self, at: usize, length: usize) -> Result<&'a [u8], PlistError> {
        let data = self.data;
        at.checked_add(length)
            .filter(|end| *end <= self.trailer.offset_table)
            .map(|end| &data[at..end])
            .ok_or_else(|| invalid(at, "object runs past the object area"))
    }

    /// Reads the object tree from `top`, depth first, with an explicit stack of the containers
    /// being filled.
    fn read(&mut self, top: usize) -> Result<Value, PlistError> {
        let mut stack: Vec<Frame> = Vec::new();
        let mut next = Step::Read(top);
        loop {
            let value = match next {
                Step::Read(index) => {
                    if stack.len() + 1 > MAX_BINARY_DEPTH {
                        return Err(PlistError::TooDeep);
                    }
                    self.budget = self
                        .budget
                        .checked_sub(1)
                        .ok_or(PlistError::ExpansionBudgetExhausted)?;
                    match self.object(index, &stack)? {
                        Object::Value(value) => value,
                        Object::Container(frame) => {
                            if !self.in_progress.insert(frame.index) {
                                return Err(invalid(frame.at, "object contains itself"));
                            }
                            stack.push(frame);
                            next = self.next_child(&mut stack);
                            continue;
                        }
                    }
                }
                Step::Finished(value) => value,
            };
            let Some(frame) = stack.last_mut() else {
                return Ok(value);
            };
            if let Some(key) = frame.add(value)? {
                let below = stack.len() - 1;
                self.anomalies.push(Anomaly::DuplicateKey {
                    path: path_text(stack[..below].iter().filter_map(Frame::segment)),
                    key,
                });
            }
            next = self.next_child(&mut stack);
        }
    }

    /// The next object the innermost container needs, or that container, finished.
    fn next_child(&mut self, stack: &mut Vec<Frame>) -> Step {
        let frame = stack.last_mut().expect("a container is open");
        if let Some(index) = frame.next_reference() {
            return Step::Read(index);
        }
        let frame = stack.pop().expect("a container is open");
        self.in_progress.remove(&frame.index);
        Step::Finished(frame.finish())
    }

    /// One object: a value, or a container to fill.
    fn object(&mut self, index: usize, stack: &[Frame]) -> Result<Object, PlistError> {
        let at = self.offsets[index];
        let marker = self.data[at];
        let low = marker & 0x0F;
        let value = match marker & 0xF0 {
            MARKER_SIMPLE => match marker {
                0x00 => Value::Null,
                0x08 => Value::Boolean(false),
                0x09 => Value::Boolean(true),
                _ => return Err(invalid(at, "unknown simple object")),
            },
            MARKER_INTEGER => self.integer(at, low, stack)?,
            MARKER_REAL => Value::Real(match low {
                2 => f64::from(f32::from_be_bytes(
                    self.bytes(at + 1, 4)?.try_into().expect("4 bytes"),
                )),
                3 => f64::from_be_bytes(self.bytes(at + 1, 8)?.try_into().expect("8 bytes")),
                _ => return Err(invalid(at, "real neither 4 nor 8 bytes")),
            }),
            _ if marker == MARKER_DATE => Value::Date(f64::from_be_bytes(
                self.bytes(at + 1, 8)?.try_into().expect("8 bytes"),
            )),
            MARKER_DATA => {
                let (count, start) = self.count(at, low)?;
                Value::Data(self.bytes(start, count)?.to_vec())
            }
            // Core Foundation reads "ASCII" strings byte for byte as ISO-8859-1.
            MARKER_ASCII => {
                let (count, start) = self.count(at, low)?;
                Value::String(
                    self.bytes(start, count)?
                        .iter()
                        .map(|byte| char::from(*byte))
                        .collect(),
                )
            }
            MARKER_UTF16 => self.utf16(at, low, stack)?,
            MARKER_UID => Value::Uid(sized_integer(self.bytes(at + 1, usize::from(low) + 1)?)),
            MARKER_ARRAY | MARKER_SET => {
                let references = self.references(at, low, 1)?;
                return Ok(Object::Container(Frame {
                    index,
                    at,
                    kind: if marker & 0xF0 == MARKER_ARRAY {
                        FrameKind::Array(Vec::new())
                    } else {
                        FrameKind::Set(Vec::new())
                    },
                    references,
                    next: 0,
                }));
            }
            MARKER_DICTIONARY => {
                let references = self.references(at, low, 2)?;
                return Ok(Object::Container(Frame {
                    index,
                    at,
                    kind: FrameKind::Dictionary {
                        dictionary: Dictionary::default(),
                        key: None,
                    },
                    references,
                    next: 0,
                }));
            }
            _ => return Err(invalid(at, "unknown object type")),
        };
        Ok(Object::Value(value))
    }

    fn utf16(&mut self, at: usize, low: u8, stack: &[Frame]) -> Result<Value, PlistError> {
        let (count, start) = self.count(at, low)?;
        let length = count
            .checked_mul(2)
            .ok_or_else(|| invalid(at, "string length overflows"))?;
        let units: Vec<u16> = self
            .bytes(start, length)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();
        let text = String::from_utf16(&units).unwrap_or_else(|_| {
            self.anomalies.push(Anomaly::InvalidUtf16 {
                path: path_text(stack.iter().filter_map(Frame::segment)),
            });
            String::from_utf16_lossy(&units)
        });
        Ok(Value::String(text))
    }

    /// 1, 2 and 4-byte integers are unsigned, 8-byte ones signed; of a 16-byte one Core
    /// Foundation keeps the low 64 bits, unsigned.
    fn integer(&mut self, at: usize, low: u8, stack: &[Frame]) -> Result<Value, PlistError> {
        let width = match low {
            0..=4 => 1usize << low,
            _ => return Err(invalid(at, "integer wider than 16 bytes")),
        };
        let bytes = self.bytes(at + 1, width)?;
        let value = match width {
            8 => i128::from(i64::from_be_bytes(bytes.try_into().expect("8 bytes"))),
            16 => {
                if bytes[..8].iter().any(|byte| *byte != 0) {
                    self.anomalies.push(Anomaly::WideInteger {
                        path: path_text(stack.iter().filter_map(Frame::segment)),
                    });
                }
                i128::from(sized_integer(&bytes[8..]))
            }
            _ => i128::from(sized_integer(bytes)),
        };
        Ok(Value::Integer(value))
    }

    /// An object's element count: the low nibble, or with 0xF an integer object after the
    /// marker. Returns the count and where the content starts.
    fn count(&self, at: usize, low: u8) -> Result<(usize, usize), PlistError> {
        if low != 0x0F {
            return Ok((usize::from(low), at + 1));
        }
        let marker = *self.bytes(at + 1, 1)?.first().expect("1 byte");
        if marker & 0xF0 != MARKER_INTEGER || marker & 0x0F > 4 {
            return Err(invalid(at + 1, "count is not an integer object"));
        }
        let width = 1usize << (marker & 0x0F);
        let bytes = self.bytes(at + 2, width)?;
        // 16-byte counts: the low 64 bits, as for integer objects.
        let value = sized_integer(&bytes[width.saturating_sub(8)..]);
        let count = usize::try_from(value)
            .ok()
            .filter(|count| *count <= self.trailer.offset_table)
            .ok_or_else(|| invalid(at + 1, "count larger than the plist"))?;
        Ok((count, at + 2 + width))
    }

    /// The object indices a container refers to: `count` references after the marker.
    fn references(&self, at: usize, low: u8, multiple: usize) -> Result<Vec<usize>, PlistError> {
        let (count, start) = self.count(at, low)?;
        let total = count
            .checked_mul(multiple)
            .and_then(|references| references.checked_mul(self.trailer.reference_size))
            .ok_or_else(|| invalid(at, "container size overflows"))?;
        let bytes = self.bytes(start, total)?;
        bytes
            .chunks_exact(self.trailer.reference_size)
            .map(|reference| {
                usize::try_from(sized_integer(reference))
                    .ok()
                    .filter(|index| *index < self.trailer.object_count)
                    .ok_or_else(|| invalid(at, "reference to an object that does not exist"))
            })
            .collect()
    }
}

/// What the walk does next: read an object, or hand a finished value to its container.
enum Step {
    Read(usize),
    Finished(Value),
}

/// An object read: a value, or a container whose items are still to be read.
enum Object {
    Value(Value),
    Container(Frame),
}

/// A container being filled.
struct Frame {
    /// Its object index, for cycle detection.
    index: usize,
    /// Its offset, for errors.
    at: usize,
    kind: FrameKind,
    /// Item references (for a dictionary: all keys, then all values).
    references: Vec<usize>,
    /// Items read so far (for a dictionary: entries completed, key and value).
    next: usize,
}

enum FrameKind {
    Array(Vec<Value>),
    Set(Vec<Value>),
    Dictionary {
        dictionary: Dictionary,
        /// The key read, waiting for its value.
        key: Option<String>,
    },
}

impl Frame {
    /// The next object to read: items in order; for a dictionary each key, then its value.
    fn next_reference(&self) -> Option<usize> {
        match &self.kind {
            FrameKind::Array(_) | FrameKind::Set(_) => self.references.get(self.next).copied(),
            FrameKind::Dictionary { key, .. } => {
                let pairs = self.references.len() / 2;
                if self.next >= pairs {
                    return None;
                }
                Some(match key {
                    None => self.references[self.next],
                    Some(_) => self.references[pairs + self.next],
                })
            }
        }
    }

    /// Takes the value just read. For a dictionary key, refuses a non-string; for a value
    /// whose key was already there, returns that key (Core Foundation keeps the first value).
    fn add(&mut self, value: Value) -> Result<Option<String>, PlistError> {
        match &mut self.kind {
            FrameKind::Array(items) | FrameKind::Set(items) => {
                items.push(value);
                self.next += 1;
                Ok(None)
            }
            FrameKind::Dictionary { dictionary, key } => match key.take() {
                None => {
                    let Value::String(text) = value else {
                        return Err(invalid(self.at, "dictionary key is not a string"));
                    };
                    *key = Some(text);
                    Ok(None)
                }
                Some(text) => {
                    self.next += 1;
                    let fresh = dictionary.insert(text.clone(), value, Format::Binary);
                    Ok((!fresh).then_some(text))
                }
            },
        }
    }

    /// Where the item being read sits in this container, for anomaly paths.
    fn segment(&self) -> Option<PathSegment<'_>> {
        match &self.kind {
            FrameKind::Array(_) | FrameKind::Set(_) => Some(PathSegment::Index(self.next)),
            FrameKind::Dictionary { key, .. } => key.as_deref().map(PathSegment::Key),
        }
    }

    fn finish(self) -> Value {
        match self.kind {
            FrameKind::Array(items) => Value::Array(items),
            FrameKind::Set(items) => Value::Set(items),
            FrameKind::Dictionary { dictionary, .. } => Value::Dictionary(dictionary),
        }
    }
}
