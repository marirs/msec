//! DER entitlements: the code signature's slot 7 blob (magic `0xfade7172`), which iOS 15 and
//! later read instead of the XML entitlements. codesign writes it from the XML:
//!
//! ```text
//! [APPLICATION 16] {            -- 0x70
//!     INTEGER version,          -- 1
//!     [CONTEXT 16] {            -- 0xb0: a dictionary
//!         SEQUENCE { UTF8String key, value } ...
//!     }
//! }
//! ```
//!
//! Values are BOOLEAN, INTEGER, UTF8String, SEQUENCE (an array) or `[CONTEXT 16]` (a nested
//! dictionary). The layout was read from codesign's output for entitlements of every value type
//! (tests/fixtures/macho/build_der_entitlements.sh); nothing else is accepted. Lengths are
//! definite (DER), nesting is bounded, and a key given twice keeps its first value, which is
//! reported.

use crate::plist::{Dictionary, Value};

/// Deepest nesting read: entitlements nest a few levels at most.
const MAX_DEPTH: usize = 32;

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_DICTIONARY: u8 = 0xb0;
const TAG_ENTITLEMENTS: u8 = 0x70;

/// Why a DER entitlements blob could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerEntitlementsError {
    /// The bytes are not the structure above; what was expected where.
    Malformed(&'static str),
    /// A version other than 1.
    Version(i128),
}

impl std::fmt::Display for DerEntitlementsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(what) => write!(formatter, "malformed DER entitlements: {what}"),
            Self::Version(version) => write!(formatter, "DER entitlements version {version}"),
        }
    }
}

/// DER entitlements, decoded.
#[derive(Debug, Clone, PartialEq)]
pub struct DerEntitlements {
    /// The entitlements.
    pub dictionary: Dictionary,
    /// Keys given more than once (the first value is kept).
    pub duplicate_keys: Vec<String>,
}

/// Decodes the blob's content (after its 8-byte header).
pub fn decode(content: &[u8]) -> Result<DerEntitlements, DerEntitlementsError> {
    let (outer, rest) = element(content)?;
    if outer.tag != TAG_ENTITLEMENTS || !rest.is_empty() {
        return Err(DerEntitlementsError::Malformed(
            "an [APPLICATION 16] element filling the blob",
        ));
    }
    let (version, rest) = element(outer.value)?;
    if version.tag != TAG_INTEGER {
        return Err(DerEntitlementsError::Malformed("the version INTEGER"));
    }
    let version = integer(version.value)?;
    if version != 1 {
        return Err(DerEntitlementsError::Version(version));
    }
    let (dictionary, rest) = element(rest)?;
    if dictionary.tag != TAG_DICTIONARY || !rest.is_empty() {
        return Err(DerEntitlementsError::Malformed(
            "a [CONTEXT 16] dictionary after the version",
        ));
    }
    let mut duplicate_keys = Vec::new();
    let dictionary = decode_dictionary(dictionary.value, 1, &mut duplicate_keys)?;
    Ok(DerEntitlements {
        dictionary,
        duplicate_keys,
    })
}

struct Element<'data> {
    tag: u8,
    value: &'data [u8],
}

/// One element with a definite length; returns it and what follows.
fn element(input: &[u8]) -> Result<(Element<'_>, &[u8]), DerEntitlementsError> {
    let truncated = DerEntitlementsError::Malformed("an element runs past its container");
    let tag = *input.first().ok_or(truncated.clone())?;
    let first = *input.get(1).ok_or(truncated.clone())?;
    let (length, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(DerEntitlementsError::Malformed(
                "a definite length of 1 to 4 bytes",
            ));
        }
        let bytes = input.get(2..2 + count).ok_or(truncated.clone())?;
        let length = bytes
            .iter()
            .fold(0usize, |length, byte| (length << 8) | *byte as usize);
        (length, 2 + count)
    };
    let end = header.checked_add(length).ok_or(truncated.clone())?;
    let value = input.get(header..end).ok_or(truncated)?;
    Ok((Element { tag, value }, &input[end..]))
}

fn integer(bytes: &[u8]) -> Result<i128, DerEntitlementsError> {
    if bytes.is_empty() || bytes.len() > 16 {
        return Err(DerEntitlementsError::Malformed(
            "an INTEGER of 1 to 16 bytes",
        ));
    }
    let negative = bytes[0] & 0x80 != 0;
    let mut value: i128 = if negative { -1 } else { 0 };
    for byte in bytes {
        value = (value << 8) | i128::from(*byte);
    }
    Ok(value)
}

fn decode_dictionary(
    mut entries: &[u8],
    depth: usize,
    duplicates: &mut Vec<String>,
) -> Result<Dictionary, DerEntitlementsError> {
    let mut dictionary = Dictionary::default();
    while !entries.is_empty() {
        let (pair, rest) = element(entries)?;
        entries = rest;
        if pair.tag != TAG_SEQUENCE {
            return Err(DerEntitlementsError::Malformed(
                "a SEQUENCE per dictionary entry",
            ));
        }
        let (key, rest) = element(pair.value)?;
        if key.tag != TAG_UTF8_STRING {
            return Err(DerEntitlementsError::Malformed("a UTF8String key"));
        }
        let key = std::str::from_utf8(key.value)
            .map_err(|_| DerEntitlementsError::Malformed("a key in UTF-8"))?
            .to_owned();
        let (value, rest) = element(rest)?;
        if !rest.is_empty() {
            return Err(DerEntitlementsError::Malformed("one value per key"));
        }
        let value = decode_value(&value, depth + 1, duplicates)?;
        if !dictionary.insert_first(key.clone(), value) {
            duplicates.push(key);
        }
    }
    Ok(dictionary)
}

fn decode_value(
    element: &Element<'_>,
    depth: usize,
    duplicates: &mut Vec<String>,
) -> Result<Value, DerEntitlementsError> {
    if depth > MAX_DEPTH {
        return Err(DerEntitlementsError::Malformed("nesting within 32 levels"));
    }
    match element.tag {
        TAG_BOOLEAN => match element.value {
            [0] => Ok(Value::Boolean(false)),
            [0xff] => Ok(Value::Boolean(true)),
            _ => Err(DerEntitlementsError::Malformed("a BOOLEAN of 00 or ff")),
        },
        TAG_INTEGER => integer(element.value).map(Value::Integer),
        TAG_UTF8_STRING => std::str::from_utf8(element.value)
            .map(|text| Value::String(text.to_owned()))
            .map_err(|_| DerEntitlementsError::Malformed("a string in UTF-8")),
        TAG_SEQUENCE => {
            let mut items = Vec::new();
            let mut rest = element.value;
            while !rest.is_empty() {
                let (item, next) = self::element(rest)?;
                items.push(decode_value(&item, depth + 1, duplicates)?);
                rest = next;
            }
            Ok(Value::Array(items))
        }
        TAG_DICTIONARY => {
            decode_dictionary(element.value, depth, duplicates).map(Value::Dictionary)
        }
        _ => Err(DerEntitlementsError::Malformed(
            "a BOOLEAN, INTEGER, UTF8String, SEQUENCE or dictionary value",
        )),
    }
}

/// Whether two entitlement sets say the same, whatever order their keys are in.
pub fn same_entitlements(left: &Dictionary, right: &Dictionary) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|(key, value)| right.get(key).is_some_and(|other| same_value(value, other)))
}

fn same_value(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Dictionary(left), Value::Dictionary(right)) => same_entitlements(left, right),
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| same_value(left, right))
        }
        _ => left == right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_blobs_are_errors_not_panics() {
        for blob in [
            &b""[..],
            b"\x70",
            b"\x70\x85\x00\x00\x00\x00\x00",
            b"\x70\x03\x02\x01\x02",
            b"\x70\x05\x02\x01\x01\xb0\x7f",
            b"\x30\x00",
        ] {
            assert!(decode(blob).is_err(), "{blob:?}");
        }
    }

    #[test]
    fn negative_and_wide_integers() {
        assert_eq!(integer(&[0xff]), Ok(-1));
        assert_eq!(integer(&[0x00, 0x80]), Ok(128));
        assert!(integer(&[]).is_err());
    }
}
