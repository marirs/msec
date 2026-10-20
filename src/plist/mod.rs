//! Property lists (`.plist`), read the way Apple's Core Foundation reads them: the binary format
//! (`bplist00`) and the XML format. iOS reads `Info.plist`, entitlements, provisioning profiles
//! and privacy manifests through Core Foundation, so msec follows its rules where they matter
//! for what an app declares:
//!
//! - a dictionary with a key twice keeps the **first** value in a binary plist and the **last**
//!   in an XML one; both are recorded as [`Anomaly::DuplicateKey`], because tools that resolve
//!   duplicates differently disagree on what the app declares;
//! - nesting deeper than Core Foundation accepts is refused, at the same depth (511 nested
//!   arrays and dictionaries in XML; 513 levels of objects in a binary plist);
//! - XML has no DTD processing: a DOCTYPE with an internal subset is refused, and only the
//!   predefined entities and character references are expanded, so entity expansion attacks
//!   cannot apply;
//! - the binary trailer, offset table and every object are bounds-checked as Core Foundation
//!   checks them, cycles are refused, and objects shared by several containers are expanded
//!   within a budget proportional to the input ([`PlistError::ExpansionBudgetExhausted`]).
//!
//! Each rule was checked against `plutil` (Core Foundation) on crafted inputs; the fixtures and
//! `plutil`'s verdicts are under `tests/fixtures/plist/`. [`to_xml`] writes a value the way
//! `plutil -convert xml1` does, which is how the tests compare msec's reading with Apple's.
//!
//! Not read: the old OpenStep text format and JSON ([`PlistError::Unsupported`]), XML in
//! encodings other than UTF-8, UTF-16 and ISO-8859-1 ([`PlistError::UnsupportedEncoding`]), and
//! binary plists of format version 1x. MobSF converts plists with Python's `plistlib`, which
//! resolves duplicate keys the same way for both formats; see `docs/PORTING.md`.

mod binary;
mod date;
mod render;
mod xml;

use std::fmt;

pub use render::{RenderError, to_xml};

/// Most nested arrays and dictionaries Core Foundation's XML parser accepts (`plutil` refuses
/// 512).
const MAX_XML_CONTAINER_DEPTH: usize = 511;
/// Deepest object Core Foundation's binary parser accepts, the top object being level 1.
const MAX_BINARY_DEPTH: usize = 513;

/// A property list value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `<string>`, or an ASCII or UTF-16 string object.
    String(String),
    /// `<integer>`. Core Foundation keeps 1, 2 and 4-byte binary integers unsigned, 8-byte
    /// ones signed, and of a 16-byte one the low 64 bits, unsigned; XML integers range from
    /// -2^63 to 2^64-1.
    Integer(i128),
    /// `<real>`.
    Real(f64),
    /// `<true/>` or `<false/>`.
    Boolean(bool),
    /// `<date>`: seconds since 2001-01-01T00:00:00Z (Core Foundation's absolute time).
    Date(f64),
    /// `<data>`.
    Data(Vec<u8>),
    /// `<array>`.
    Array(Vec<Value>),
    /// `<dict>`.
    Dictionary(Dictionary),
    /// A keyed-archiver UID (binary plists only). Written in XML as a dictionary with the one
    /// key `CF$UID`.
    Uid(u64),
    /// A binary null object, which Core Foundation reads but cannot write as XML.
    Null,
    /// A binary set, which Core Foundation reads but cannot write as XML.
    Set(Vec<Value>),
}

impl Value {
    /// The string, when this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// The boolean, when this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// The integer, when this is one.
    pub fn as_integer(&self) -> Option<i128> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// The array's items, when this is one.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The dictionary, when this is one.
    pub fn as_dictionary(&self) -> Option<&Dictionary> {
        match self {
            Self::Dictionary(dictionary) => Some(dictionary),
            _ => None,
        }
    }

    /// The value for `key`, when this is a dictionary that has it.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_dictionary()?.get(key)
    }

    /// The type's name in XML (`string`, `dict`, ...), for messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::String(_) => "string",
            Self::Integer(_) => "integer",
            Self::Real(_) => "real",
            Self::Boolean(_) => "boolean",
            Self::Date(_) => "date",
            Self::Data(_) => "data",
            Self::Array(_) => "array",
            Self::Dictionary(_) => "dict",
            Self::Uid(_) => "uid",
            Self::Null => "null",
            Self::Set(_) => "set",
        }
    }
}

/// A dictionary as Core Foundation holds it: each key once (which duplicate survives depends on
/// the format; see [`Anomaly::DuplicateKey`]), in the order the plist first names them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Dictionary {
    entries: Vec<(String, Value)>,
}

impl Dictionary {
    /// The value for `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    /// Keys and values, in the order the plist first names the keys.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No keys.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds a key the way Core Foundation's parser for `format` does: a binary plist keeps the
    /// first value, an XML one the last. Returns false when the key was already there.
    fn insert(&mut self, key: String, value: Value, format: Format) -> bool {
        match self
            .entries
            .iter_mut()
            .find(|(candidate, _)| *candidate == key)
        {
            None => {
                self.entries.push((key, value));
                true
            }
            Some(entry) => {
                if format == Format::Xml {
                    entry.1 = value;
                }
                false
            }
        }
    }
}

/// Which of the two formats a plist was in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// `bplist00`.
    Binary,
    /// XML.
    Xml,
}

/// Something in a plist Core Foundation accepts but that deserves attention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    /// A dictionary names a key more than once. Core Foundation keeps the first value in a
    /// binary plist and the last in an XML one; parsers that differ (Python's `plistlib` keeps
    /// the last for both) see a different value, the kind of disagreement behind past iOS
    /// entitlement bypasses. `path` locates the dictionary (`/CFBundleURLTypes/0`).
    DuplicateKey {
        /// Where the dictionary is.
        path: String,
        /// The repeated key.
        key: String,
    },
    /// A UTF-16 string with an unpaired surrogate. Core Foundation keeps the code unit; msec
    /// substitutes U+FFFD.
    InvalidUtf16 {
        /// Where the string is.
        path: String,
    },
    /// A 16-byte binary integer beyond 64 bits: Core Foundation uses its low 64 bits.
    WideInteger {
        /// Where the integer is.
        path: String,
    },
}

/// Why a plist could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlistError {
    /// Not a format msec reads: empty input, OpenStep text, JSON, or binary format 1x.
    Unsupported(&'static str),
    /// XML declared in an encoding other than UTF-8, UTF-16 and ISO-8859-1.
    UnsupportedEncoding(String),
    /// The binary structure is invalid at `offset`.
    InvalidBinary {
        /// Byte offset in the plist.
        offset: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// The XML is not a well-formed plist at `offset`.
    InvalidXml {
        /// Byte offset in the decoded text.
        offset: usize,
        /// What is wrong.
        reason: String,
    },
    /// Nested deeper than Core Foundation accepts.
    TooDeep,
    /// Objects shared by several containers expand past msec's budget. Core Foundation shares
    /// them instead and reads the plist.
    ExpansionBudgetExhausted,
}

impl PlistError {
    /// Core Foundation refuses this plist too (checked against `plutil` for each kind). False
    /// for formats and encodings msec does not read, and for the expansion budget, where Core
    /// Foundation reads what msec does not.
    pub fn rejected_by_core_foundation(&self) -> bool {
        match self {
            Self::InvalidBinary { .. } | Self::InvalidXml { .. } | Self::TooDeep => true,
            Self::Unsupported(_)
            | Self::UnsupportedEncoding(_)
            | Self::ExpansionBudgetExhausted => false,
        }
    }
}

impl fmt::Display for PlistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(what) => write!(formatter, "not supported: {what}"),
            Self::UnsupportedEncoding(encoding) => {
                write!(formatter, "XML encoding {encoding:?} is not supported")
            }
            Self::InvalidBinary { offset, reason } => {
                write!(formatter, "invalid binary plist at byte {offset}: {reason}")
            }
            Self::InvalidXml { offset, reason } => {
                write!(formatter, "invalid XML plist at byte {offset}: {reason}")
            }
            Self::TooDeep => formatter.write_str("nested deeper than Core Foundation accepts"),
            Self::ExpansionBudgetExhausted => {
                formatter.write_str("shared objects expand past the reading budget")
            }
        }
    }
}

impl std::error::Error for PlistError {}

/// A plist read in full.
#[derive(Debug, Clone, PartialEq)]
pub struct Plist {
    /// The format it was in.
    pub format: Format,
    /// The top-level value.
    pub root: Value,
    /// What deserves attention.
    pub anomalies: Vec<Anomaly>,
}

/// Reads a binary or XML plist.
pub fn parse(bytes: &[u8]) -> Result<Plist, PlistError> {
    if bytes.starts_with(b"bplist") {
        return binary::parse(bytes);
    }
    xml::parse(bytes)
}

/// One step of a path into a plist: an array position or a dictionary key.
#[derive(Clone, Copy)]
enum PathSegment<'a> {
    Index(usize),
    Key(&'a str),
}

/// `/CFBundleURLTypes/0`: where a value is, for anomalies. `/` is the top level.
fn path_text<'a>(segments: impl IntoIterator<Item = PathSegment<'a>>) -> String {
    let mut text = String::new();
    for segment in segments {
        text.push('/');
        match segment {
            PathSegment::Index(index) => text.push_str(&index.to_string()),
            PathSegment::Key(key) => text.push_str(key),
        }
    }
    if text.is_empty() {
        text.push('/');
    }
    text
}
