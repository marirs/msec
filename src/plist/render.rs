//! Writes a value as XML exactly as `plutil -convert xml1` (Core Foundation's XML writer)
//! does, so the tests can compare msec's reading of a plist with Apple's byte for byte:
//! dictionary keys sorted by UTF-16 code unit, one tab per level, `&`, `<` and `>` escaped,
//! reals with 17 significant digits (`%.17g`; zero as `0.0`), dates to the second, and base64
//! in lines of 76 characters less 8 per level of indentation (at most 8 levels).

use std::fmt::{self, Write as _};

use super::Value;
use super::date::civil_from_absolute;

const HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n";
/// Base64 line width at the top level; each level of indentation (up to the 8th) takes 8.
const BASE64_LINE: usize = 76;
const BASE64_INDENT_LIMIT: usize = 8;

/// What Core Foundation cannot write as XML either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderError {
    /// A null or set object (binary plists only).
    NotRepresentable(&'static str),
    /// A string with a NUL character.
    NulInString,
    /// A date no civil date can show.
    DateOutOfRange,
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRepresentable(kind) => write!(formatter, "a {kind} cannot be written as XML"),
            Self::NulInString => {
                formatter.write_str("a string with a NUL cannot be written as XML")
            }
            Self::DateOutOfRange => formatter.write_str("a date out of range"),
        }
    }
}

impl std::error::Error for RenderError {}

/// The XML document `plutil -convert xml1` writes for `value`.
pub fn to_xml(value: &Value) -> Result<String, RenderError> {
    let mut output = String::from(HEADER);
    write_value(&mut output, value, 0)?;
    output.push_str("</plist>\n");
    Ok(output)
}

fn indent(output: &mut String, level: usize) {
    output.extend(std::iter::repeat_n('\t', level));
}

fn write_value(output: &mut String, value: &Value, level: usize) -> Result<(), RenderError> {
    indent(output, level);
    match value {
        Value::String(text) => {
            output.push_str("<string>");
            escape(output, text)?;
            output.push_str("</string>\n");
        }
        Value::Integer(number) => {
            let _ = writeln!(output, "<integer>{number}</integer>");
        }
        Value::Real(number) => {
            let _ = writeln!(output, "<real>{}</real>", format_real(*number));
        }
        Value::Boolean(true) => output.push_str("<true/>\n"),
        Value::Boolean(false) => output.push_str("<false/>\n"),
        Value::Date(absolute) => {
            let time = civil_from_absolute(*absolute).ok_or(RenderError::DateOutOfRange)?;
            let _ = writeln!(
                output,
                "<date>{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z</date>",
                time.year, time.month, time.day, time.hour, time.minute, time.second
            );
        }
        Value::Data(bytes) => write_data(output, bytes, level),
        Value::Array(items) if items.is_empty() => output.push_str("<array/>\n"),
        Value::Array(items) => {
            output.push_str("<array>\n");
            for item in items {
                write_value(output, item, level + 1)?;
            }
            indent(output, level);
            output.push_str("</array>\n");
        }
        Value::Dictionary(dictionary) if dictionary.is_empty() => output.push_str("<dict/>\n"),
        Value::Dictionary(dictionary) => {
            output.push_str("<dict>\n");
            let mut entries: Vec<(&str, &Value)> = dictionary.iter().collect();
            entries.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            for (key, item) in entries {
                indent(output, level + 1);
                output.push_str("<key>");
                escape(output, key)?;
                output.push_str("</key>\n");
                write_value(output, item, level + 1)?;
            }
            indent(output, level);
            output.push_str("</dict>\n");
        }
        Value::Uid(uid) => {
            output.push_str("<dict>\n");
            indent(output, level + 1);
            output.push_str("<key>CF$UID</key>\n");
            indent(output, level + 1);
            let _ = writeln!(output, "<integer>{uid}</integer>");
            indent(output, level);
            output.push_str("</dict>\n");
        }
        Value::Null => return Err(RenderError::NotRepresentable("null")),
        Value::Set(_) => return Err(RenderError::NotRepresentable("set")),
    }
    Ok(())
}

fn escape(output: &mut String, text: &str) -> Result<(), RenderError> {
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\0' => return Err(RenderError::NulInString),
            other => output.push(other),
        }
    }
    Ok(())
}

/// `<data>`, its base64 lines, `</data>`: lines indented by the element's level up to 8 tabs,
/// each 76 characters less 8 per tab.
fn write_data(output: &mut String, bytes: &[u8], level: usize) {
    output.push_str("<data>\n");
    let data_indent = level.min(BASE64_INDENT_LIMIT);
    let width = BASE64_LINE - 8 * data_indent;
    let encoded = base64(bytes);
    for line in encoded.as_bytes().chunks(width) {
        indent(output, data_indent);
        output.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        output.push('\n');
    }
    indent(output, level);
    output.push_str("</data>\n");
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = chunk.iter().enumerate().fold(0u32, |group, (index, byte)| {
            group | u32::from(*byte) << (16 - 8 * index)
        });
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(char::from(
                    ALPHABET[(group >> (18 - 6 * index)) as usize & 63],
                ));
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// C's `%.17g`, with Core Foundation's spellings for zero, infinities and NaN.
fn format_real(number: f64) -> String {
    if number == 0.0 {
        return "0.0".to_owned();
    }
    if number.is_nan() {
        return "nan".to_owned();
    }
    if number.is_infinite() {
        return if number > 0.0 {
            "+infinity"
        } else {
            "-infinity"
        }
        .to_owned();
    }
    const PRECISION: i32 = 17;
    let scientific = format!("{:.*e}", (PRECISION - 1) as usize, number);
    let (mantissa, exponent) = scientific.split_once('e').expect("Rust writes an exponent");
    let exponent: i32 = exponent.parse().expect("integer exponent");
    if !(-4..PRECISION).contains(&exponent) {
        let mantissa = trim_fraction(mantissa);
        let sign = if exponent < 0 { '-' } else { '+' };
        return format!("{mantissa}e{sign}{:02}", exponent.abs());
    }
    let decimals = (PRECISION - 1 - exponent) as usize;
    trim_fraction(&format!("{number:.decimals$}")).to_owned()
}

/// `%g` drops trailing zeros of the fraction, and the point when nothing is left.
fn trim_fraction(text: &str) -> &str {
    if !text.contains('.') {
        return text;
    }
    text.trim_end_matches('0').trim_end_matches('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spellings `plutil -convert xml1` wrote for the same values.
    #[test]
    #[allow(clippy::approx_constant)] // 3.14 is the value plutil was given, not an attempt at π
    fn reals_are_written_like_printf_g17() {
        for (number, text) in [
            (3.14, "3.1400000000000001"),
            (1.0, "1"),
            (1e300, "1.0000000000000001e+300"),
            (5e-324, "4.9406564584124654e-324"),
            (0.1, "0.10000000000000001"),
            (123_456_789_012_345_678.0, "1.2345678901234568e+17"),
            (1e16, "10000000000000000"),
            (1e17, "1e+17"),
            (0.0001, "0.0001"),
            (0.00001, "1.0000000000000001e-05"),
            (-2.5, "-2.5"),
            (1e21, "1e+21"),
            (123.456, "123.456"),
            (-0.0, "0.0"),
            (f64::INFINITY, "+infinity"),
            (f64::NEG_INFINITY, "-infinity"),
        ] {
            assert_eq!(format_real(number), text, "{number:e}");
        }
        assert_eq!(format_real(f64::NAN), "nan");
    }

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"A"), "QQ==");
        assert_eq!(base64(b"AB"), "QUI=");
        assert_eq!(base64(b"ABC"), "QUJD");
        assert_eq!(base64(&[0, 1, 2, 3]), "AAECAw==");
    }
}
