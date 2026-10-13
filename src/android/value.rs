//! `Res_value`: the typed values of binary XML attributes and resource table entries.

use std::fmt;

const TYPE_NULL: u8 = 0x00;
const TYPE_REFERENCE: u8 = 0x01;
const TYPE_ATTRIBUTE: u8 = 0x02;
const TYPE_STRING: u8 = 0x03;
const TYPE_FLOAT: u8 = 0x04;
const TYPE_DIMENSION: u8 = 0x05;
const TYPE_FRACTION: u8 = 0x06;
const TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
const TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;
const TYPE_FIRST_COLOR_INT: u8 = 0x1c;
const TYPE_LAST_COLOR_INT: u8 = 0x1f;

/// `TYPE_NULL` with this data means "empty", not "undefined".
const DATA_NULL_EMPTY: u32 = 1;

/// A typed value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// No value (`TYPE_NULL`, undefined).
    Null,
    /// Explicitly empty (`TYPE_NULL` with `DATA_NULL_EMPTY`).
    Empty,
    /// Reference to a resource (`@...`).
    Reference(u32),
    /// Reference to a theme attribute (`?...`).
    Attribute(u32),
    /// A string. `None` when the string index is out of range.
    String(Option<String>),
    /// Floating point number.
    Float(f32),
    /// Dimension with its unit.
    Dimension(f32, &'static str),
    /// Fraction, `%` or `%p`.
    Fraction(f32, &'static str),
    /// Decimal integer.
    Integer(i32),
    /// Hexadecimal integer (flags and enums).
    Hex(u32),
    /// Boolean.
    Boolean(bool),
    /// ARGB colour.
    Color(u32),
    /// Any other type, kept raw.
    Other {
        /// The `Res_value` data type.
        data_type: u8,
        /// The raw data.
        data: u32,
    },
}

impl Value {
    /// Decodes `data` of `data_type`. `string` resolves string pool indices.
    pub(crate) fn decode(data_type: u8, data: u32, string: impl Fn(u32) -> Option<String>) -> Self {
        match data_type {
            TYPE_NULL if data == DATA_NULL_EMPTY => Self::Empty,
            TYPE_NULL => Self::Null,
            // Dynamic references point into shared libraries; for analysis they read the same.
            TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE => Self::Reference(data),
            TYPE_ATTRIBUTE | TYPE_DYNAMIC_ATTRIBUTE => Self::Attribute(data),
            TYPE_STRING => Self::String(string(data)),
            TYPE_FLOAT => Self::Float(f32::from_bits(data)),
            TYPE_DIMENSION => Self::Dimension(complex_value(data), dimension_unit(data)),
            TYPE_FRACTION => Self::Fraction(complex_value(data) * 100.0, fraction_unit(data)),
            TYPE_INT_DEC => Self::Integer(data as i32),
            TYPE_INT_HEX => Self::Hex(data),
            TYPE_INT_BOOLEAN => Self::Boolean(data != 0),
            TYPE_FIRST_COLOR_INT..=TYPE_LAST_COLOR_INT => Self::Color(data),
            other => Self::Other {
                data_type: other,
                data,
            },
        }
    }

    /// The string, when this is a string value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(Some(text)) => Some(text),
            _ => None,
        }
    }

    /// The value as Android's `TypedArray.getBoolean` reads it: integers are true when non-zero,
    /// strings `true`/`false`/digits are converted.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            Self::Integer(value) => Some(*value != 0),
            Self::Hex(value) | Self::Color(value) => Some(*value != 0),
            Self::String(Some(text)) => {
                let text = text.trim();
                if text.eq_ignore_ascii_case("true") {
                    Some(true)
                } else if text.eq_ignore_ascii_case("false") {
                    Some(false)
                } else {
                    parse_integer(text).map(|value| value != 0)
                }
            }
            _ => None,
        }
    }

    /// The value as an integer, the way Android's `TypedArray.getInt` converts it.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(i64::from(*value)),
            Self::Hex(value) | Self::Color(value) => Some(i64::from(*value)),
            Self::Boolean(value) => Some(i64::from(*value)),
            Self::String(Some(text)) => parse_integer(text.trim()),
            _ => None,
        }
    }

    /// The resource ID, when this is a reference.
    pub fn reference(&self) -> Option<u32> {
        match self {
            Self::Reference(id) => Some(*id),
            _ => None,
        }
    }
}

/// Decimal, `0x` hexadecimal or `#` hexadecimal, as `XmlUtils.convertValueToInt` accepts.
fn parse_integer(text: &str) -> Option<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = digits.strip_prefix('#') {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        digits.parse().ok()?
    };
    Some(if negative { -value } else { value })
}

/// Complex values (dimensions, fractions): 24-bit signed mantissa and a radix in bits 4-5.
fn complex_value(data: u32) -> f32 {
    const MANTISSA_MULTIPLIER: f32 = 1.0 / 256.0;
    const RADIX_MULTIPLIERS: [f32; 4] = [
        MANTISSA_MULTIPLIER,
        MANTISSA_MULTIPLIER / 128.0,
        MANTISSA_MULTIPLIER / 32_768.0,
        MANTISSA_MULTIPLIER / 8_388_608.0,
    ];
    let mantissa = (data & 0xffff_ff00) as i32 as f32;
    mantissa * RADIX_MULTIPLIERS[((data >> 4) & 0x3) as usize]
}

fn dimension_unit(data: u32) -> &'static str {
    match data & 0xf {
        0 => "px",
        1 => "dp",
        2 => "sp",
        3 => "pt",
        4 => "in",
        5 => "mm",
        _ => "",
    }
}

fn fraction_unit(data: u32) -> &'static str {
    if data & 0xf == 1 { "%p" } else { "%" }
}

impl fmt::Display for Value {
    /// The notation of `aapt2 dump xmltree`, so output can be compared with Android tooling.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => Ok(()),
            Self::Empty => write!(formatter, "@empty"),
            Self::Reference(id) => write!(formatter, "@0x{id:08x}"),
            Self::Attribute(id) => write!(formatter, "?0x{id:08x}"),
            Self::String(Some(text)) => write!(formatter, "{text}"),
            Self::String(None) => write!(formatter, "(invalid string)"),
            Self::Float(value) => write!(formatter, "{value}"),
            Self::Dimension(value, unit) | Self::Fraction(value, unit) => {
                write!(formatter, "{value}{unit}")
            }
            Self::Integer(value) => write!(formatter, "{value}"),
            Self::Hex(value) => write!(formatter, "0x{value:08x}"),
            Self::Boolean(value) => write!(formatter, "{value}"),
            Self::Color(value) => write!(formatter, "#{value:08x}"),
            Self::Other { data_type, data } => {
                write!(formatter, "(type 0x{data_type:02x})0x{data:08x}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_strings(_: u32) -> Option<String> {
        None
    }

    #[test]
    fn decodes_common_types() {
        assert_eq!(
            Value::decode(TYPE_INT_BOOLEAN, 0xffff_ffff, no_strings),
            Value::Boolean(true)
        );
        assert_eq!(
            Value::decode(TYPE_INT_DEC, 24, no_strings),
            Value::Integer(24)
        );
        assert_eq!(
            Value::decode(TYPE_REFERENCE, 0x7f0a_0001, no_strings),
            Value::Reference(0x7f0a_0001)
        );
        assert_eq!(Value::decode(TYPE_NULL, 1, no_strings), Value::Empty);
        // 16dp: mantissa 16 << 8, radix 0, unit 1.
        assert_eq!(
            Value::decode(TYPE_DIMENSION, (16 << 8) | 1, no_strings),
            Value::Dimension(16.0, "dp")
        );
        let resolved = Value::decode(TYPE_STRING, 0, |_| Some("x".to_owned()));
        assert_eq!(resolved.as_str(), Some("x"));
    }

    #[test]
    fn converts_like_typed_array() {
        assert_eq!(Value::String(Some("TRUE".into())).as_bool(), Some(true));
        assert_eq!(Value::String(Some("0".into())).as_bool(), Some(false));
        assert_eq!(Value::String(Some("0x10".into())).as_integer(), Some(16));
        assert_eq!(Value::String(Some("Tiramisu".into())).as_integer(), None);
        assert_eq!(Value::Integer(0).as_bool(), Some(false));
    }
}
