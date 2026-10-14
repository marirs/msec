//! A bounded reader for the protobuf wire format, enough for the messages app bundles store:
//! aapt2's XML (`Resources.proto`: `XmlNode` and what it contains) and bundletool's
//! `BundleConfig.pb`.
//!
//! Hand-written instead of generated (ADR-0004 planned `prost`): msec reads a handful of
//! messages, and every length here is checked against the bytes present, so no input can make
//! the reader allocate or read past the buffer. Unknown fields are skipped, as protobuf
//! requires; groups (wire types 3 and 4, unused by proto3) are an error.

/// Why a message could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtoProblem {
    /// A varint runs past the end or past ten bytes.
    BadVarint,
    /// A length-delimited field runs past the end of its message.
    LengthPastEnd,
    /// A fixed-size field runs past the end.
    Truncated,
    /// Wire type 3, 4, 6 or 7.
    UnsupportedWireType(u8),
    /// Field number 0.
    ZeroFieldNumber,
    /// A field expected to be a varint, string or message has another wire type.
    WrongWireType,
    /// A string field is not UTF-8.
    InvalidUtf8,
}

/// One field's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireValue<'data> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'data [u8]),
    Fixed32(u32),
}

impl<'data> WireValue<'data> {
    pub(crate) fn bytes(self) -> Result<&'data [u8], ProtoProblem> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            _ => Err(ProtoProblem::WrongWireType),
        }
    }

    pub(crate) fn string(self) -> Result<&'data str, ProtoProblem> {
        std::str::from_utf8(self.bytes()?).map_err(|_| ProtoProblem::InvalidUtf8)
    }

    pub(crate) fn varint(self) -> Result<u64, ProtoProblem> {
        match self {
            Self::Varint(value) => Ok(value),
            _ => Err(ProtoProblem::WrongWireType),
        }
    }

    /// A `uint32` field: protobuf truncates wider varints to 32 bits.
    pub(crate) fn uint32(self) -> Result<u32, ProtoProblem> {
        Ok(self.varint()? as u32)
    }

    /// A `float` field.
    pub(crate) fn float(self) -> Result<f32, ProtoProblem> {
        match self {
            Self::Fixed32(bits) => Ok(f32::from_bits(bits)),
            _ => Err(ProtoProblem::WrongWireType),
        }
    }
}

/// Iterates over the fields of one message.
pub(crate) struct Fields<'data> {
    bytes: &'data [u8],
    position: usize,
    failed: bool,
}

impl<'data> Fields<'data> {
    pub(crate) fn new(bytes: &'data [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            failed: false,
        }
    }

    fn varint(&mut self) -> Result<u64, ProtoProblem> {
        let mut value: u64 = 0;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(ProtoProblem::BadVarint)?;
            self.position += 1;
            // The tenth byte may only carry the top bit of a 64-bit value; protobuf decoders
            // drop what does not fit, and so does this one.
            if shift < 64 {
                value |= u64::from(byte & 0x7f) << shift;
            }
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ProtoProblem::BadVarint)
    }

    fn take(&mut self, length: usize, problem: ProtoProblem) -> Result<&'data [u8], ProtoProblem> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(problem)?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn field(&mut self) -> Result<(u32, WireValue<'data>), ProtoProblem> {
        let key = self.varint()?;
        let number = u32::try_from(key >> 3).unwrap_or(u32::MAX);
        if number == 0 {
            return Err(ProtoProblem::ZeroFieldNumber);
        }
        let value = match (key & 7) as u8 {
            0 => WireValue::Varint(self.varint()?),
            1 => {
                let bytes = self.take(8, ProtoProblem::Truncated)?;
                WireValue::Fixed64(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
            }
            2 => {
                let length = usize::try_from(self.varint()?).unwrap_or(usize::MAX);
                WireValue::Bytes(self.take(length, ProtoProblem::LengthPastEnd)?)
            }
            5 => {
                let bytes = self.take(4, ProtoProblem::Truncated)?;
                WireValue::Fixed32(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
            }
            other => return Err(ProtoProblem::UnsupportedWireType(other)),
        };
        Ok((number, value))
    }
}

impl<'data> Iterator for Fields<'data> {
    type Item = Result<(u32, WireValue<'data>), ProtoProblem>;

    /// The next field; after an error, nothing more.
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.position >= self.bytes.len() {
            return None;
        }
        let field = self.field();
        self.failed = field.is_err();
        Some(field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_read_and_bounded() {
        // 1: varint 150; 2: "hi"; 5: fixed32 1.0; 3: fixed64 7.
        let bytes = [
            0x08, 0x96, 0x01, 0x12, 0x02, b'h', b'i', 0x2d, 0x00, 0x00, 0x80, 0x3f, 0x19, 7, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let fields: Vec<_> = Fields::new(&bytes).collect::<Result<_, _>>().unwrap();
        assert_eq!(fields[0], (1, WireValue::Varint(150)));
        assert_eq!(fields[1].1.string(), Ok("hi"));
        assert_eq!(fields[2].1.float(), Ok(1.0));
        assert_eq!(fields[3], (3, WireValue::Fixed64(7)));

        let problem = |bytes: &[u8]| Fields::new(bytes).find_map(Result::err);
        assert_eq!(
            problem(&[0x12, 0x05, b'h']),
            Some(ProtoProblem::LengthPastEnd)
        );
        assert_eq!(problem(&[0x08, 0x80]), Some(ProtoProblem::BadVarint));
        assert_eq!(problem(&[0x0b]), Some(ProtoProblem::UnsupportedWireType(3)));
        assert_eq!(problem(&[0x00, 0x00]), Some(ProtoProblem::ZeroFieldNumber));
        assert_eq!(problem(&[0x2d, 0x00]), Some(ProtoProblem::Truncated));
        // A length that would overflow when added to the position.
        assert_eq!(
            problem(&[
                0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
            ]),
            Some(ProtoProblem::LengthPastEnd)
        );
    }
}
