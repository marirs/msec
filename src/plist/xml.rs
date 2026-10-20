//! The XML format, parsed with Core Foundation's rules (`CFPropertyList.c`), each confirmed with
//! `plutil` on the fixtures in `tests/fixtures/plist/xml/`. This is not a general XML parser:
//!
//! - before the root: whitespace, `<?...?>`, comments and a DOCTYPE without an internal subset
//!   (`[` is refused, so no entity can be declared); after it, anything (ignored);
//! - the root is `<plist>` holding exactly one value, or a value element on its own;
//! - a tag ends at its first `>` (attributes are skipped without quote handling, as Core
//!   Foundation skips them); element names are case-sensitive;
//! - text in `<string>` and `<key>`: the five predefined entities, character references and
//!   CDATA sections; any other markup in text is refused (even a comment);
//! - `<integer>`: leading whitespace, a sign, more whitespace, then decimal or `0x` hex digits,
//!   from -2^63 to 2^64-1, nothing after; `<real>`: leading whitespace then a decimal number,
//!   `inf`, `infinity` or `nan` (no hex floats, nothing after); `<date>`:
//!   `[-]YYYY-MM-DDTHH:MM:SSZ` exactly, out-of-range fields carried; `<data>`: base64 decoded
//!   the lenient way Core Foundation decodes it; `<true/>` and `<false/>` empty;
//! - `<key>` outside a dictionary is a string; in a dictionary keys and values alternate, and
//!   a repeated key keeps the **last** value;
//! - at most 511 nested arrays and dictionaries, walked with an explicit stack rather than
//!   recursion, so that depth never depends on the caller's thread stack.

use super::date::{CivilTime, absolute_from_civil};
use super::{
    Anomaly, Dictionary, Format, MAX_XML_CONTAINER_DEPTH, PathSegment, Plist, PlistError, Value,
    path_text,
};

pub(super) fn parse(bytes: &[u8]) -> Result<Plist, PlistError> {
    let text = decode(bytes)?;
    let mut parser = Parser {
        text: &text,
        position: 0,
        anomalies: Vec::new(),
    };
    let root = parser.document()?;
    Ok(Plist {
        format: Format::Xml,
        root,
        anomalies: parser.anomalies,
    })
}

/// The document as text: UTF-8 (with or without a byte-order mark), UTF-16 with a byte-order
/// mark, or ISO-8859-1 when the XML declaration names it.
fn decode(bytes: &[u8]) -> Result<String, PlistError> {
    let invalid = |reason: &str| PlistError::InvalidXml {
        offset: 0,
        reason: reason.to_owned(),
    };
    if let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        return String::from_utf8(rest.to_vec()).map_err(|_| invalid("invalid UTF-8"));
    }
    let utf16 = |rest: &[u8], big_endian: bool| {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                if big_endian {
                    u16::from_be_bytes(*pair)
                } else {
                    u16::from_le_bytes(*pair)
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16"))
    };
    if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
        return utf16(rest, false);
    }
    if let Some(rest) = bytes.strip_prefix(b"\xFE\xFF") {
        return utf16(rest, true);
    }
    let first = bytes.iter().find(|byte| !is_whitespace(char::from(**byte)));
    match first {
        None => return Err(PlistError::Unsupported("empty input")),
        Some(b'<') => {}
        Some(_) => return Err(PlistError::Unsupported("OpenStep or JSON text")),
    }
    match declared_encoding(bytes).as_deref() {
        None | Some("utf-8" | "utf8") => {
            String::from_utf8(bytes.to_vec()).map_err(|_| invalid("invalid UTF-8"))
        }
        Some("iso-8859-1" | "iso_8859-1" | "latin1" | "latin-1") => {
            Ok(bytes.iter().map(|byte| char::from(*byte)).collect())
        }
        Some(other) => Err(PlistError::UnsupportedEncoding(other.to_owned())),
    }
}

/// The `encoding` of a leading `<?xml ...?>` declaration, lower-cased.
fn declared_encoding(bytes: &[u8]) -> Option<String> {
    let start = bytes.iter().position(|byte| *byte == b'<')?;
    let rest = &bytes[start..];
    if !rest.starts_with(b"<?xml") {
        return None;
    }
    let end = rest.windows(2).position(|pair| pair == b"?>")?;
    let declaration = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
    let after = &declaration[declaration.find("encoding")? + "encoding".len()..];
    let after = after.trim_start().strip_prefix('=')?.trim_start();
    let quote = after.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let value = &after[1..];
    Some(value[..value.find(quote)?].to_owned())
}

/// XML whitespace, which Core Foundation skips between elements.
fn is_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r')
}

/// C's `isspace`, which Core Foundation uses inside values.
fn is_c_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r' | '\x0B' | '\x0C')
}

/// An open tag: its name and whether it closed itself (`<true/>`).
struct OpenTag<'a> {
    name: &'a str,
    empty: bool,
    at: usize,
}

/// What the walk does next: read the element a tag opens, or hand a finished value to its
/// container.
enum Step<'a> {
    Open(OpenTag<'a>),
    Finished(Value),
}

/// An array or dictionary being filled.
enum Container {
    Array(Vec<Value>),
    Dictionary {
        dictionary: Dictionary,
        /// The key read, waiting for its value.
        key: Option<String>,
    },
}

impl Container {
    fn new(dictionary: bool) -> Self {
        if dictionary {
            Self::Dictionary {
                dictionary: Dictionary::default(),
                key: None,
            }
        } else {
            Self::Array(Vec::new())
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Array(_) => "array",
            Self::Dictionary { .. } => "dict",
        }
    }

    /// Takes the value just read; returns its key when the dictionary already had it (Core
    /// Foundation's XML reader keeps the last value).
    fn add(&mut self, value: Value) -> Option<String> {
        match self {
            Self::Array(items) => {
                items.push(value);
                None
            }
            Self::Dictionary { dictionary, key } => {
                let key = key.take().expect("a value follows its key");
                (!dictionary.insert(key.clone(), value, Format::Xml)).then_some(key)
            }
        }
    }

    /// Where the item being read sits in this container, for anomaly paths.
    fn segment(&self) -> Option<PathSegment<'_>> {
        match self {
            Self::Array(items) => Some(PathSegment::Index(items.len())),
            Self::Dictionary { key, .. } => key.as_deref().map(PathSegment::Key),
        }
    }

    fn finish(self) -> Value {
        match self {
            Self::Array(items) => Value::Array(items),
            Self::Dictionary { dictionary, .. } => Value::Dictionary(dictionary),
        }
    }
}

struct Parser<'a> {
    text: &'a str,
    position: usize,
    anomalies: Vec<Anomaly>,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.position..]
    }

    fn error<T>(&self, reason: impl Into<String>) -> Result<T, PlistError> {
        Err(PlistError::InvalidXml {
            offset: self.position,
            reason: reason.into(),
        })
    }

    fn skip_whitespace(&mut self) {
        let skipped = self.rest().len() - self.rest().trim_start_matches(is_whitespace).len();
        self.position += skipped;
    }

    /// Skips past `terminator`, which must follow.
    fn skip_past(&mut self, terminator: &str, what: &str) -> Result<(), PlistError> {
        match self.rest().find(terminator) {
            Some(index) => {
                self.position += index + terminator.len();
                Ok(())
            }
            None => self.error(format!("unterminated {what}")),
        }
    }

    /// Skips whitespace, comments and processing instructions.
    fn skip_misc(&mut self) -> Result<(), PlistError> {
        loop {
            self.skip_whitespace();
            if self.rest().starts_with("<?") {
                self.skip_past("?>", "processing instruction")?;
            } else if self.rest().starts_with("<!--") {
                self.skip_past("-->", "comment")?;
            } else {
                return Ok(());
            }
        }
    }

    fn document(&mut self) -> Result<Value, PlistError> {
        loop {
            self.skip_misc()?;
            if self.rest().starts_with("<!DOCTYPE") {
                self.doctype()?;
                continue;
            }
            if !self.rest().starts_with('<') {
                if self.rest().is_empty() {
                    return self.error("no root element");
                }
                return self.error("unexpected character while looking for open tag");
            }
            let tag = self.open_tag()?;
            if tag.name != "plist" {
                return self.value(tag);
            }
            if tag.empty {
                return self.error("empty plist tag");
            }
            self.skip_misc()?;
            if self.rest().starts_with("</") {
                return self.error("empty plist tag");
            }
            if !self.rest().starts_with('<') {
                return self.error("unexpected character while looking for open tag");
            }
            let inner = self.open_tag()?;
            let value = self.value(inner)?;
            self.skip_misc()?;
            if self.rest().starts_with("</") {
                self.close_tag("plist")?;
                // Anything after the root is ignored, as Core Foundation ignores it.
                return Ok(value);
            }
            if self.rest().starts_with('<') {
                return self.error("plist can only include one object");
            }
            return self.error("unexpected character while looking for close tag");
        }
    }

    /// `<!DOCTYPE ...>` up to its `>`; an internal subset (`[`) is refused, as Core
    /// Foundation refuses it, so no entity can ever be declared.
    fn doctype(&mut self) -> Result<(), PlistError> {
        let rest = self.rest();
        let end = rest.find(['>', '[']);
        match end.map(|index| (index, rest.as_bytes()[index])) {
            Some((index, b'>')) => {
                self.position += index + 1;
                Ok(())
            }
            Some((index, _)) => {
                self.position += index;
                self.error("DTD internal subset")
            }
            None => self.error("unterminated DOCTYPE"),
        }
    }

    /// `<name ...>` or `<name .../>`: the tag ends at its first `>`.
    fn open_tag(&mut self) -> Result<OpenTag<'a>, PlistError> {
        let at = self.position;
        let rest = &self.rest()[1..];
        let name_length = rest
            .find(|character: char| {
                is_whitespace(character) || character == '/' || character == '>'
            })
            .unwrap_or(rest.len());
        let name = &rest[..name_length];
        let Some(end) = rest.find('>') else {
            return self.error("unexpected EOF");
        };
        let empty = rest[..end].ends_with('/');
        self.position += 1 + end + 1;
        Ok(OpenTag { name, empty, at })
    }

    /// `</name>`, with optional whitespace before the `>`.
    fn close_tag(&mut self, name: &str) -> Result<(), PlistError> {
        let rest = &self.rest()[2..];
        let Some(end) = rest.find('>') else {
            return self.error("unexpected EOF");
        };
        if rest[..end].trim_end_matches(is_whitespace) != name {
            return self.error(format!("close tag does not match open tag {name}"));
        }
        self.position += 2 + end + 1;
        Ok(())
    }

    /// The value an open tag starts, with every array and dictionary inside it.
    fn value(&mut self, tag: OpenTag<'a>) -> Result<Value, PlistError> {
        let mut stack: Vec<Container> = Vec::new();
        let mut next = Step::Open(tag);
        loop {
            let value = match next {
                Step::Open(tag) => match tag.name {
                    "array" | "dict" => {
                        if stack.len() >= MAX_XML_CONTAINER_DEPTH {
                            return Err(PlistError::TooDeep);
                        }
                        let container = Container::new(tag.name == "dict");
                        if tag.empty {
                            container.finish()
                        } else {
                            stack.push(container);
                            next = self.next_child(&mut stack)?;
                            continue;
                        }
                    }
                    _ => self.scalar(tag)?,
                },
                Step::Finished(value) => value,
            };
            let Some(container) = stack.last_mut() else {
                return Ok(value);
            };
            if let Some(key) = container.add(value) {
                let below = stack.len() - 1;
                self.anomalies.push(Anomaly::DuplicateKey {
                    path: path_text(stack[..below].iter().filter_map(Container::segment)),
                    key,
                });
            }
            next = self.next_child(&mut stack)?;
        }
    }

    /// What the innermost container holds next: an element to read (for a dictionary, the
    /// value after its key, the key read here), or its close tag, which finishes it.
    fn next_child(&mut self, stack: &mut Vec<Container>) -> Result<Step<'a>, PlistError> {
        self.skip_misc()?;
        if self.rest().starts_with("</") {
            let container = stack.pop().expect("a container is open");
            self.close_tag(container.name())?;
            return Ok(Step::Finished(container.finish()));
        }
        if !self.rest().starts_with('<') {
            if self.rest().is_empty() {
                return self.error("unexpected EOF");
            }
            return self.error("unexpected character while looking for open tag");
        }
        let tag = self.open_tag()?;
        let container = stack.last_mut().expect("a container is open");
        let Container::Dictionary { key, .. } = container else {
            return Ok(Step::Open(tag));
        };
        if tag.name != "key" {
            self.position = tag.at;
            return self.error("found non-key inside <dict>");
        }
        *key = Some(self.text_content(&tag)?);
        self.skip_misc()?;
        if !self.rest().starts_with('<') || self.rest().starts_with("</") {
            return self.error("value missing for key inside <dict>");
        }
        Ok(Step::Open(self.open_tag()?))
    }

    /// A value that is not a container.
    fn scalar(&mut self, tag: OpenTag<'a>) -> Result<Value, PlistError> {
        match tag.name {
            "string" | "key" => Ok(Value::String(self.text_content(&tag)?)),
            "true" | "false" => {
                if !tag.empty {
                    if !self.rest().starts_with("</") {
                        return self.error(format!("non-empty <{}>", tag.name));
                    }
                    self.close_tag(tag.name)?;
                }
                Ok(Value::Boolean(tag.name == "true"))
            }
            "integer" => {
                let raw = self.raw_content(&tag)?;
                parse_integer(raw).map(Value::Integer).or_else(|reason| {
                    self.position = tag.at;
                    self.error(reason)
                })
            }
            "real" => {
                let raw = self.raw_content(&tag)?;
                parse_real(raw).map(Value::Real).ok_or(()).or_else(|()| {
                    self.position = tag.at;
                    self.error("misformatted real")
                })
            }
            "date" => {
                let raw = self.raw_content(&tag)?;
                parse_date(raw).map(Value::Date).ok_or(()).or_else(|()| {
                    self.position = tag.at;
                    self.error("could not interpret <date>")
                })
            }
            "data" => {
                let raw = self.raw_content(&tag)?;
                Ok(Value::Data(decode_base64(raw)))
            }
            other => {
                self.position = tag.at;
                self.error(format!("unknown tag {other}"))
            }
        }
    }

    /// Text of `<string>` or `<key>`: entities, character references and CDATA.
    fn text_content(&mut self, tag: &OpenTag<'a>) -> Result<String, PlistError> {
        let mut text = String::new();
        if tag.empty {
            return Ok(text);
        }
        loop {
            let rest = self.rest();
            let Some(index) = rest.find(['<', '&']) else {
                return self.error("unexpected EOF");
            };
            text.push_str(&rest[..index]);
            self.position += index;
            let rest = self.rest();
            if rest.starts_with("</") {
                self.close_tag(tag.name)?;
                return Ok(text);
            }
            if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
                let Some(end) = cdata.find("]]>") else {
                    return self.error("unterminated CDATA");
                };
                text.push_str(&cdata[..end]);
                self.position += "<![CDATA[".len() + end + "]]>".len();
                continue;
            }
            if rest.starts_with("<!") {
                return self.error("improper CDATA opening");
            }
            if rest.starts_with('<') {
                return self.error("unexpected character while looking for close tag");
            }
            text.push(self.entity()?);
        }
    }

    /// `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;`, `&#65;` or `&#x41;`.
    fn entity(&mut self) -> Result<char, PlistError> {
        let rest = self.rest();
        let Some(end) = rest.find(';').filter(|end| *end <= 12) else {
            return self.error("unknown ampersand-escape sequence");
        };
        let name = &rest[1..end];
        let character = match name {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                let code = if let Some(hex) = name.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(decimal) = name.strip_prefix('#') {
                    decimal.parse::<u32>().ok()
                } else {
                    return self.error("unknown ampersand-escape sequence");
                };
                match code.and_then(char::from_u32) {
                    Some(character) => Some(character),
                    None => return self.error("unparseable Unicode sequence"),
                }
            }
        };
        self.position += end + 1;
        Ok(character.expect("matched"))
    }

    /// Raw text up to the closing tag, for numbers, dates and data (no markup inside). A
    /// self-closed or empty element is refused, as Core Foundation refuses it, except
    /// `<data></data>`.
    fn raw_content(&mut self, tag: &OpenTag<'a>) -> Result<&'a str, PlistError> {
        if tag.empty {
            return self.error(format!("empty <{}>", tag.name));
        }
        let rest = self.rest();
        let Some(end) = rest.find('<') else {
            return self.error("unexpected EOF");
        };
        let raw = &rest[..end];
        self.position += end;
        if !self.rest().starts_with("</") {
            return self.error("unexpected character while looking for close tag");
        }
        self.close_tag(tag.name)?;
        if raw.is_empty() && tag.name != "data" && tag.name != "real" && tag.name != "date" {
            self.position = tag.at;
            return self.error(format!("empty <{}>", tag.name));
        }
        Ok(raw)
    }
}

/// `<integer>` content: whitespace, sign, whitespace, decimal or `0x` hex digits, nothing
/// after; from -2^63 to 2^64-1.
fn parse_integer(raw: &str) -> Result<i128, String> {
    let rest = raw.trim_start_matches(is_c_space);
    let (negative, rest) = match rest.as_bytes().first() {
        Some(b'-') => (true, &rest[1..]),
        Some(b'+') => (false, &rest[1..]),
        _ => (false, rest),
    };
    let rest = rest.trim_start_matches(is_c_space);
    let (radix, digits) = match rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None => (10, rest),
    };
    if digits.is_empty() {
        return Err("incomplete <integer>".to_owned());
    }
    let mut magnitude: u128 = 0;
    for character in digits.chars() {
        let digit = match character.to_digit(16) {
            Some(digit) if digit < radix => digit,
            Some(_) => return Err("hex digit in non-hex <integer>".to_owned()),
            None => return Err(format!("unknown character {character:?} in <integer>")),
        };
        magnitude = magnitude * u128::from(radix) + u128::from(digit);
        if magnitude > u128::from(u64::MAX) + 1 {
            magnitude = u128::from(u64::MAX) + 1;
        }
    }
    if negative {
        if magnitude > 1u128 << 63 {
            return Err("integer underflow in <integer>".to_owned());
        }
        Ok(-(magnitude as i128))
    } else {
        if magnitude > u128::from(u64::MAX) {
            return Err("integer overflow in <integer>".to_owned());
        }
        Ok(magnitude as i128)
    }
}

/// `<real>` content: leading whitespace, then a decimal number, `inf`, `infinity` or `nan`
/// (any case, optionally signed except `nan`), nothing after. No hexadecimal floats.
fn parse_real(raw: &str) -> Option<f64> {
    let rest = raw.trim_start_matches(is_c_space);
    let unsigned = rest.strip_prefix(['+', '-']).unwrap_or(rest);
    if unsigned.eq_ignore_ascii_case("nan") && unsigned.len() == rest.len() {
        return Some(f64::NAN);
    }
    if unsigned.eq_ignore_ascii_case("inf") || unsigned.eq_ignore_ascii_case("infinity") {
        let infinity = f64::INFINITY;
        return Some(if rest.starts_with('-') {
            -infinity
        } else {
            infinity
        });
    }
    let decimal = unsigned
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-'));
    if !decimal || unsigned.is_empty() {
        return None;
    }
    rest.parse::<f64>().ok()
}

/// `<date>` content: `[-]YYYY-MM-DDTHH:MM:SSZ` (any number of year digits, the rest exactly
/// two), nothing around it.
fn parse_date(raw: &str) -> Option<f64> {
    let (negative, rest) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    let year_digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if year_digits == 0 || year_digits > 12 {
        return None;
    }
    let year: i64 = rest[..year_digits].parse().ok()?;
    let rest = &rest[year_digits..];
    let bytes = rest.as_bytes();
    // "-MM-DDTHH:MM:SSZ"
    if bytes.len() != 16 {
        return None;
    }
    let separators = [
        (0, b'-'),
        (3, b'-'),
        (6, b'T'),
        (9, b':'),
        (12, b':'),
        (15, b'Z'),
    ];
    if separators
        .iter()
        .any(|(index, byte)| bytes[*index] != *byte)
    {
        return None;
    }
    let field = |start: usize| -> Option<i64> {
        let digits = &bytes[start..start + 2];
        digits
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| i64::from((digits[0] - b'0') * 10 + (digits[1] - b'0')))
    };
    absolute_from_civil(CivilTime {
        year: if negative { -year } else { year },
        month: field(1)?,
        day: field(4)?,
        hour: field(7)?,
        minute: field(10)?,
        second: field(13)?,
    })
}

/// Core Foundation's base64 reading: characters outside the alphabet are skipped, `=` counts
/// as a zero digit, every four digits give three bytes less one per trailing `=`, and an
/// incomplete last group is dropped.
fn decode_base64(raw: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(raw.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut digits = 0usize;
    let mut equals = 0usize;
    for character in raw.chars() {
        if character == '=' {
            equals += 1;
        } else if !is_c_space(character) {
            equals = 0;
        }
        let digit = match character {
            'A'..='Z' => character as u32 - 'A' as u32,
            'a'..='z' => character as u32 - 'a' as u32 + 26,
            '0'..='9' => character as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => 0,
            _ => continue,
        };
        digits += 1;
        accumulator = (accumulator << 6) | digit;
        if digits.is_multiple_of(4) {
            bytes.push((accumulator >> 16) as u8);
            if equals < 2 {
                bytes.push((accumulator >> 8) as u8);
            }
            if equals < 1 {
                bytes.push(accumulator as u8);
            }
            accumulator = 0;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_follow_core_foundation() {
        for (raw, value) in [
            ("0x10", 16),
            ("+5", 5),
            ("-0x10", -16),
            ("0X1f", 31),
            ("18446744073709551615", 18_446_744_073_709_551_615),
            ("-9223372036854775808", -9_223_372_036_854_775_808),
            ("007", 7),
            (" 7", 7),
            ("+ 7", 7),
            ("\n5", 5),
        ] {
            assert_eq!(parse_integer(raw), Ok(value), "{raw:?}");
        }
        for raw in [
            "18446744073709551616",
            "-9223372036854775809",
            "1_0",
            "-",
            "0x",
            "1e3",
            "7 ",
            "0x 1",
        ] {
            assert!(parse_integer(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn reals_follow_core_foundation() {
        for (raw, value) in [
            ("2.5", 2.5),
            (".5", 0.5),
            ("5.", 5.0),
            ("+1.5", 1.5),
            ("1E5", 100_000.0),
            (" 2.5", 2.5),
            ("1e-400", 0.0),
        ] {
            assert_eq!(parse_real(raw), Some(value), "{raw:?}");
        }
        for raw in ["inf", "Infinity", "+infinity", "1e400"] {
            assert_eq!(parse_real(raw), Some(f64::INFINITY), "{raw:?}");
        }
        assert_eq!(parse_real("-infinity"), Some(f64::NEG_INFINITY));
        assert!(parse_real("NaN").unwrap().is_nan());
        for raw in [
            "0x1p3", "1.5x", "2.5\n", "2.5 ", "+nan", "infinit", "", "abc",
        ] {
            assert_eq!(parse_real(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn base64_is_read_leniently() {
        assert_eq!(decode_base64(" AA EC\n Aw== "), [0, 1, 2, 3]);
        assert_eq!(decode_base64("AA==AAEC"), [0, 0, 1, 2]);
        assert_eq!(decode_base64("AAE"), [] as [u8; 0]);
        assert_eq!(decode_base64("!!!!"), [] as [u8; 0]);
        assert_eq!(decode_base64("QQ=="), b"A");
    }

    #[test]
    fn dates_are_exact() {
        assert_eq!(parse_date("2001-01-01T00:00:00Z"), Some(0.0));
        assert!(parse_date("12026-01-02T03:04:05Z").is_some());
        assert!(parse_date("-001-01-01T00:00:00Z").is_some());
        for raw in [
            "2026-01-02T03:04:05.75Z",
            "2026-01-02T03:04:05",
            "2026-01-02",
            "2026-01-02T03:04:05+01:00",
            " 2026-01-02T03:04:05Z",
            "2026-1-02T03:04:05Z",
            "+2026-01-02T03:04:05Z",
            "",
        ] {
            assert_eq!(parse_date(raw), None, "{raw:?}");
        }
    }
}
