//! Old-style (OpenStep) text property lists, and `.strings` files (a dictionary's entries
//! without the braces), read the way Core Foundation reads them. iOS reads an app's
//! `InfoPlist.strings` this way when it is not a binary or XML plist (Xcode writes binary ones;
//! other toolchains ship text).
//!
//! The rules below were each checked against `plutil` (tests/fixtures/plist, `openstep/`):
//!
//! - text is UTF-16 with a byte-order mark (a trailing odd byte is dropped), or UTF-8 (with or
//!   without a byte-order mark); anything else is refused;
//! - whitespace includes U+2028 and U+2029; `//` and `/* */` comments are skipped, and an
//!   unterminated block comment runs to the end of the text;
//! - values are quoted strings (`"..."` or `'...'`), unquoted strings of
//!   `[A-Za-z0-9_$/:.-]`, arrays `( a, b, )` (a trailing comma is allowed), dictionaries
//!   `{ key = value; }` (every entry ends with `;`, and `key;` means `key = key;`) and data
//!   `<0a1b ...>`;
//! - escapes: `\a \b \f \n \r \t \v`; one to three octal digits, a byte in the NeXTSTEP
//!   encoding (two bytes have no character and are refused); `\U` and one to four hex digits,
//!   a UTF-16 code unit (two make a surrogate pair); any other character stands for itself;
//! - a text whose first value is a string, followed by more, is a `.strings` file and reads as
//!   a dictionary; after its last entry, anything that cannot start a key ends the reading
//!   (`;;` reads), while text after any other top-level value is refused; text that is only
//!   whitespace and comments is an empty dictionary;
//! - a key given twice keeps the last value (recorded as [`Anomaly::DuplicateKey`]);
//! - an object nested deeper than 513 levels, the top being level 1, is refused.
//!
//! Text starting with `<` is XML (Core Foundation does not try OpenStep then), and JSON is
//! not a property list format Core Foundation reads.

use super::{Anomaly, Dictionary, Format, Plist, PlistError, Value};

/// Deepest object Core Foundation's OpenStep parser accepts, the top object being level 1.
const MAX_DEPTH: usize = 513;

/// Bytes 0x80 to 0xFD of the NeXTSTEP encoding as UTF-16, for octal escapes. Read from
/// `iconv -f NEXTSTEP` and checked against `plutil` for every byte; 0xFE and 0xFF have no
/// character, and Core Foundation refuses them.
const NEXTSTEP_HIGH: [u16; 126] = [
    0x00a0, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c7, 0x00c8, 0x00c9, 0x00ca, 0x00cb,
    0x00cc, 0x00cd, 0x00ce, 0x00cf, 0x00d0, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d9,
    0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00b5, 0x00d7, 0x00f7, 0x00a9, 0x00a1, 0x00a2, 0x00a3,
    0x2044, 0x00a5, 0x0192, 0x00a7, 0x00a4, 0x2019, 0x201c, 0x00ab, 0x2039, 0x203a, 0xfb01, 0xfb02,
    0x00ae, 0x2013, 0x2020, 0x2021, 0x00b7, 0x00a6, 0x00b6, 0x2022, 0x201a, 0x201e, 0x201d, 0x00bb,
    0x2026, 0x2030, 0x00ac, 0x00bf, 0x00b9, 0x02cb, 0x00b4, 0x02c6, 0x02dc, 0x00af, 0x02d8, 0x02d9,
    0x00a8, 0x00b2, 0x02da, 0x00b8, 0x00b3, 0x02dd, 0x02db, 0x02c7, 0x2014, 0x00b1, 0x00bc, 0x00bd,
    0x00be, 0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb,
    0x00ec, 0x00c6, 0x00ed, 0x00aa, 0x00ee, 0x00ef, 0x00f0, 0x00f1, 0x0141, 0x00d8, 0x0152, 0x00ba,
    0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00e6, 0x00f9, 0x00fa, 0x00fb, 0x0131, 0x00fc, 0x00fd,
    0x0142, 0x00f8, 0x0153, 0x00df, 0x00fe, 0x00ff,
];

/// Whether `bytes` (not a binary plist) is OpenStep text rather than XML: its first character
/// that is not whitespace, after any byte-order mark, is not `<`. Empty input is neither.
pub(super) fn is_openstep(bytes: &[u8]) -> bool {
    let first = match decode(bytes) {
        Ok(units) => units.into_iter().find(|unit| !is_space(*unit)),
        // Not UTF-8: XML may declare another encoding, so judge by the first byte.
        Err(_) => bytes
            .iter()
            .map(|byte| u16::from(*byte))
            .find(|unit| !is_space(*unit)),
    };
    match first {
        Some(unit) => unit != u16::from(b'<'),
        None => !bytes.is_empty(),
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Plist, PlistError> {
    let text = decode(bytes)?;
    let mut parser = Parser {
        text: &text,
        position: 0,
        anomalies: Vec::new(),
        path: Vec::new(),
    };
    let root = parser.document()?;
    Ok(Plist {
        format: Format::OpenStep,
        root,
        anomalies: parser.anomalies,
    })
}

/// The text as UTF-16 code units, as Core Foundation parses it.
fn decode(bytes: &[u8]) -> Result<Vec<u16>, PlistError> {
    let utf16 = |rest: &[u8], big_endian: bool| -> Result<Vec<u16>, PlistError> {
        // A trailing odd byte is dropped, as Core Foundation drops it.
        let (pairs, _) = rest.as_chunks::<2>();
        Ok(pairs
            .iter()
            .map(|pair| {
                if big_endian {
                    u16::from_be_bytes(*pair)
                } else {
                    u16::from_le_bytes(*pair)
                }
            })
            .collect())
    };
    if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
        return utf16(rest, false);
    }
    if let Some(rest) = bytes.strip_prefix(b"\xFE\xFF") {
        return utf16(rest, true);
    }
    let rest = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    std::str::from_utf8(rest)
        .map(|text| text.encode_utf16().collect())
        .map_err(|error| invalid(error.valid_up_to(), "invalid UTF-8"))
}

fn invalid(offset: usize, reason: &str) -> PlistError {
    PlistError::InvalidOpenStep {
        offset,
        reason: reason.to_owned(),
    }
}

/// Whitespace as Core Foundation's OpenStep parser skips it.
fn is_space(unit: u16) -> bool {
    (9..=13).contains(&unit) || unit == u16::from(b' ') || unit == 0x2028 || unit == 0x2029
}

/// A character an unquoted string may hold.
fn is_unquoted(unit: u16) -> bool {
    u8::try_from(unit).is_ok_and(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'/' | b':' | b'.' | b'-')
    })
}

const QUOTE: u16 = b'"' as u16;
const APOSTROPHE: u16 = b'\'' as u16;

struct Parser<'a> {
    text: &'a [u16],
    /// Position in `text`, in UTF-16 code units.
    position: usize,
    anomalies: Vec<Anomaly>,
    /// Keys and indexes down to the value being read, for anomalies.
    path: Vec<String>,
}

impl Parser<'_> {
    fn error(&self, reason: &str) -> PlistError {
        invalid(self.position, reason)
    }

    fn peek(&self) -> Option<u16> {
        self.text.get(self.position).copied()
    }

    fn next_unit(&mut self) -> Option<u16> {
        let unit = self.peek()?;
        self.position += 1;
        Some(unit)
    }

    /// Skips whitespace and comments; false at the end of the text.
    fn skip_space(&mut self) -> bool {
        while let Some(unit) = self.peek() {
            if is_space(unit) {
                self.position += 1;
                continue;
            }
            if unit == u16::from(b'/') {
                match self.text.get(self.position + 1).copied() {
                    Some(next) if next == u16::from(b'/') => {
                        self.position += 2;
                        while let Some(unit) = self.peek() {
                            if matches!(unit, 10 | 13 | 0x2028 | 0x2029) {
                                break;
                            }
                            self.position += 1;
                        }
                        continue;
                    }
                    Some(next) if next == u16::from(b'*') => {
                        self.position += 2;
                        // An unterminated comment runs to the end of the text.
                        self.position = self.text[self.position..]
                            .windows(2)
                            .position(|pair| pair == [u16::from(b'*'), u16::from(b'/')])
                            .map_or(self.text.len(), |end| self.position + end + 2);
                        continue;
                    }
                    _ => {}
                }
            }
            return true;
        }
        false
    }

    fn document(&mut self) -> Result<Value, PlistError> {
        if !self.skip_space() {
            return Ok(Value::Dictionary(Dictionary::default()));
        }
        let start = self.position;
        let first = self
            .object(1)?
            .ok_or_else(|| self.error("no property list value"))?;
        if !self.skip_space() {
            return Ok(first);
        }
        if !matches!(first, Value::String(_)) {
            return Err(self.error("text after the property list"));
        }
        // A string followed by more: a .strings file, read again as a dictionary's entries.
        self.position = start;
        self.anomalies.clear();
        Ok(Value::Dictionary(self.dictionary_entries(1)?))
    }

    /// One value at nesting `level`; `None` when the next character cannot start one.
    fn object(&mut self, level: usize) -> Result<Option<Value>, PlistError> {
        if !self.skip_space() {
            return Ok(None);
        }
        let unit = self.peek().unwrap_or_default();
        let opens = b"{(<".map(u16::from).contains(&unit)
            || unit == QUOTE
            || unit == APOSTROPHE
            || is_unquoted(unit);
        if !opens {
            return Ok(None);
        }
        if level > MAX_DEPTH {
            return Err(PlistError::TooDeep);
        }
        let value = match u8::try_from(unit).unwrap_or_default() {
            b'{' => {
                self.position += 1;
                let dictionary = self.dictionary_entries(level)?;
                if !self.skip_space() || self.peek() != Some(u16::from(b'}')) {
                    return Err(self.error("expected '}' to end the dictionary"));
                }
                self.position += 1;
                Value::Dictionary(dictionary)
            }
            b'(' => {
                self.position += 1;
                Value::Array(self.array(level)?)
            }
            b'<' => {
                self.position += 1;
                Value::Data(self.data()?)
            }
            _ => Value::String(self.string_body()?),
        };
        Ok(Some(value))
    }

    /// A required value after `=` at `level`.
    fn required_object(&mut self, level: usize) -> Result<Value, PlistError> {
        match self.object(level)? {
            Some(value) => Ok(value),
            None if self.position >= self.text.len() => {
                Err(self.error("the text ends where a value should be"))
            }
            None => Err(self.error("unexpected character where a value should be")),
        }
    }

    /// A quoted or unquoted string at `level`; `None` when the next character cannot start one.
    fn string(&mut self, level: usize) -> Result<Option<String>, PlistError> {
        if !self.skip_space() {
            return Ok(None);
        }
        let unit = self.peek().unwrap_or_default();
        if !(unit == QUOTE || unit == APOSTROPHE || is_unquoted(unit)) {
            return Ok(None);
        }
        if level > MAX_DEPTH {
            return Err(PlistError::TooDeep);
        }
        self.string_body().map(Some)
    }

    /// The string at the current position (its first character is a quote or an unquoted
    /// character).
    fn string_body(&mut self) -> Result<String, PlistError> {
        let first = self.peek().unwrap_or_default();
        let units = if first == QUOTE || first == APOSTROPHE {
            self.position += 1;
            self.quoted(first)?
        } else {
            let start = self.position;
            while self.peek().is_some_and(is_unquoted) {
                self.position += 1;
            }
            self.text[start..self.position].to_vec()
        };
        Ok(match String::from_utf16(&units) {
            Ok(text) => text,
            Err(_) => {
                // Core Foundation keeps an unpaired surrogate; UTF-8 cannot.
                self.anomalies.push(Anomaly::InvalidUtf16 {
                    path: self.path_text(),
                });
                String::from_utf16_lossy(&units)
            }
        })
    }

    fn quoted(&mut self, quote: u16) -> Result<Vec<u16>, PlistError> {
        let start = self.position;
        let mut units = Vec::new();
        loop {
            let Some(unit) = self.next_unit() else {
                self.position = start;
                return Err(self.error("unterminated quoted string"));
            };
            if unit == quote {
                return Ok(units);
            }
            if unit != u16::from(b'\\') {
                units.push(unit);
                continue;
            }
            let Some(escaped) = self.next_unit() else {
                self.position = start;
                return Err(self.error("unterminated quoted string"));
            };
            units.push(self.escape(escaped)?);
        }
    }

    /// The character an escape stands for; `escaped` follows the backslash.
    fn escape(&mut self, escaped: u16) -> Result<u16, PlistError> {
        let octal = |unit: Option<u16>| unit.filter(|unit| (0x30..=0x37).contains(unit));
        if let Some(first) = octal(Some(escaped)) {
            // Up to three digits, accumulated in a byte as Core Foundation does.
            let mut byte = (first - 0x30) as u8;
            for _ in 0..2 {
                let Some(digit) = octal(self.peek()) else {
                    break;
                };
                self.position += 1;
                byte = byte.wrapping_shl(3).wrapping_add((digit - 0x30) as u8);
            }
            return match byte {
                0..=0x7f => Ok(u16::from(byte)),
                0x80..=0xfd => Ok(NEXTSTEP_HIGH[usize::from(byte - 0x80)]),
                _ => Err(self.error("an octal escape names no NeXTSTEP character")),
            };
        }
        let character = u8::try_from(escaped).unwrap_or_default();
        Ok(match character {
            b'U' => {
                let mut value: u16 = 0;
                let mut digits = 0;
                while digits < 4 {
                    let Some(digit) = self
                        .peek()
                        .and_then(|unit| char::from_u32(u32::from(unit)))
                        .and_then(|unit| unit.to_digit(16))
                    else {
                        break;
                    };
                    self.position += 1;
                    value = (value << 4) | digit as u16;
                    digits += 1;
                }
                if digits == 0 {
                    return Err(self.error("\\U without hex digits"));
                }
                value
            }
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'n' => 10,
            b'r' => 13,
            b't' => 9,
            b'v' => 11,
            _ => escaped,
        })
    }

    /// Entries up to the first character that cannot start a key, for a dictionary at `level`.
    fn dictionary_entries(&mut self, level: usize) -> Result<Dictionary, PlistError> {
        let mut dictionary = Dictionary::default();
        while let Some(key) = self.string(level + 1)? {
            if !self.skip_space() {
                return Err(self.error("expected '=' or ';' after the key"));
            }
            self.path.push(key.clone());
            let value = if self.peek() == Some(u16::from(b';')) {
                // `key;` is `key = key;` (the .strings shorthand).
                Value::String(key.clone())
            } else if self.peek() == Some(u16::from(b'=')) {
                self.position += 1;
                self.required_object(level + 1)?
            } else {
                return Err(self.error("expected '=' or ';' after the key"));
            };
            self.path.pop();
            if !dictionary.insert(key.clone(), value, Format::OpenStep) {
                self.anomalies.push(Anomaly::DuplicateKey {
                    path: self.path_text(),
                    key,
                });
            }
            if !self.skip_space() || self.peek() != Some(u16::from(b';')) {
                return Err(self.error("expected ';' after the entry"));
            }
            self.position += 1;
        }
        Ok(dictionary)
    }

    fn array(&mut self, level: usize) -> Result<Vec<Value>, PlistError> {
        let mut items = Vec::new();
        self.path.push(items.len().to_string());
        let mut next = self.object(level + 1)?;
        self.path.pop();
        while let Some(item) = next {
            items.push(item);
            if !self.skip_space() {
                return Err(self.error("expected ',' or ')' in the array"));
            }
            if self.peek() != Some(u16::from(b',')) {
                break;
            }
            self.position += 1;
            self.path.push(items.len().to_string());
            next = self.object(level + 1)?;
            self.path.pop();
        }
        if !self.skip_space() || self.peek() != Some(u16::from(b')')) {
            return Err(self.error("expected ')' to end the array"));
        }
        self.position += 1;
        Ok(items)
    }

    /// Hex digit pairs up to `>`, whitespace between them skipped.
    fn data(&mut self) -> Result<Vec<u8>, PlistError> {
        let hex = |unit: Option<u16>| {
            unit.and_then(|unit| char::from_u32(u32::from(unit)))
                .and_then(|unit| unit.to_digit(16))
        };
        let mut bytes = Vec::new();
        while let Some(unit) = self.peek() {
            if unit == u16::from(b'>') {
                self.position += 1;
                return Ok(bytes);
            }
            if matches!(unit, 9 | 10 | 13 | 0x20 | 0x2028 | 0x2029) {
                self.position += 1;
                continue;
            }
            let (Some(high), Some(low)) = (
                hex(Some(unit)),
                hex(self.text.get(self.position + 1).copied()),
            ) else {
                return Err(self.error("data is not pairs of hex digits"));
            };
            bytes.push((high * 16 + low) as u8);
            self.position += 2;
        }
        Err(self.error("unterminated data"))
    }

    /// `/a/0`: where the value being read is.
    fn path_text(&self) -> String {
        if self.path.is_empty() {
            return "/".to_owned();
        }
        self.path.iter().map(|part| format!("/{part}")).collect()
    }
}
