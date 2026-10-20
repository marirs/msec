//! aapt2's protobuf XML (`XmlNode` in AOSP `frameworks/base/tools/aapt2/Resources.proto`): the
//! format of manifests and `res/xml` files inside Android App Bundles, which bundletool turns
//! into binary XML when it builds the APKs Google Play serves. Decoded into the same
//! [`XmlDocument`] as binary XML, so the manifest model and its checks read both alike.
//!
//! Differences from binary XML that the tree keeps: attributes stay in source order (binary XML
//! sorts them by resource ID), whitespace between elements is kept as text nodes, and the raw
//! source text of every attribute is kept (references are also named there, `@string/app_name`,
//! while [`Value::Reference`] holds only the ID, as in binary XML).
//!
//! A message that is not valid protobuf fails the whole document, as it fails protobuf's own
//! parser (and with it bundletool): [`XmlError::InvalidProtobuf`].

use super::proto::{Fields, ProtoProblem};
use super::value::{TYPE_DIMENSION, TYPE_FRACTION, Value};
use super::xml::{
    MAX_DEPTH, Namespace, XmlAnomaly, XmlAnomalyKind, XmlAttribute, XmlDocument, XmlElement,
    XmlError, XmlNode, attribute_identity_anomaly,
};

/// `XmlNode` fields.
const NODE_ELEMENT: u32 = 1;
const NODE_TEXT: u32 = 2;
const NODE_SOURCE: u32 = 3;
/// `XmlElement` fields.
const ELEMENT_NAMESPACE_DECLARATION: u32 = 1;
const ELEMENT_NAMESPACE_URI: u32 = 2;
const ELEMENT_NAME: u32 = 3;
const ELEMENT_ATTRIBUTE: u32 = 4;
const ELEMENT_CHILD: u32 = 5;
/// `XmlNamespace` fields.
const NAMESPACE_PREFIX: u32 = 1;
const NAMESPACE_URI: u32 = 2;
const NAMESPACE_SOURCE: u32 = 3;
/// `XmlAttribute` fields.
const ATTRIBUTE_NAMESPACE_URI: u32 = 1;
const ATTRIBUTE_NAME: u32 = 2;
const ATTRIBUTE_VALUE: u32 = 3;
const ATTRIBUTE_RESOURCE_ID: u32 = 5;
const ATTRIBUTE_COMPILED_ITEM: u32 = 6;
/// `SourcePosition.line_number`.
const SOURCE_LINE: u32 = 1;
/// `Item` oneof fields.
const ITEM_REFERENCE: u32 = 1;
const ITEM_STRING: u32 = 2;
const ITEM_RAW_STRING: u32 = 3;
const ITEM_STYLED_STRING: u32 = 4;
const ITEM_FILE: u32 = 5;
const ITEM_ID: u32 = 6;
const ITEM_PRIMITIVE: u32 = 7;
/// `Reference` fields; `type` 1 is `ATTRIBUTE` (`?attr`), 0 `REFERENCE` (`@type/name`).
const REFERENCE_TYPE: u32 = 1;
const REFERENCE_ID: u32 = 2;
const REFERENCE_TYPE_ATTRIBUTE: u64 = 1;
/// The `value` field of `String`, `RawString`, `StyledString`; `path` of `FileReference`.
const TEXT_VALUE: u32 = 1;

/// Which of the two XML formats a file is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XmlFormat {
    /// Binary XML (`ResXMLTree`): what Android installs and reads, in APKs.
    Binary,
    /// aapt2's protobuf XML: what app bundles store; Android cannot read it.
    Protobuf,
}

impl XmlFormat {
    /// Binary XML starts with its chunk type (`RES_XML_TYPE`, `03 00`); protobuf XML with an
    /// `XmlNode` field key (`0a` element, `12` text, `1a` source). `None` for anything else.
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [0x03, 0x00, ..] => Some(Self::Binary),
            [0x0a | 0x12 | 0x1a, ..] => Some(Self::Protobuf),
            _ => None,
        }
    }
}

/// Decodes a protobuf XML file.
pub fn parse_proto(bytes: &[u8]) -> Result<XmlDocument, XmlError> {
    let mut decoder = Decoder {
        base: bytes.as_ptr() as usize,
        namespaces: Vec::new(),
        anomalies: Vec::new(),
    };
    let root = match decoder.node(bytes, 0) {
        Ok(Some(XmlNode::Element(element))) => Some(element),
        Ok(_) => None,
        Err(problem) => return Err(XmlError::InvalidProtobuf(problem)),
    };
    if root.is_none() {
        decoder.anomalies.push(XmlAnomaly {
            kind: XmlAnomalyKind::NoElements,
            offset: 0,
        });
    }
    Ok(XmlDocument {
        root,
        namespaces: decoder.namespaces,
        anomalies: decoder.anomalies,
    })
}

struct Decoder {
    /// Address of the document's first byte, to turn sub-slices into offsets.
    base: usize,
    namespaces: Vec<Namespace>,
    anomalies: Vec<XmlAnomaly>,
}

impl Decoder {
    /// Byte offset of a sub-slice of the document.
    fn offset(&self, slice: &[u8]) -> usize {
        (slice.as_ptr() as usize).saturating_sub(self.base)
    }

    /// An `XmlNode`: `None` for a node that is neither element nor text, or one skipped past the
    /// depth limit.
    fn node(&mut self, bytes: &[u8], depth: usize) -> Result<Option<XmlNode>, ProtoProblem> {
        let mut element: Option<&[u8]> = None;
        let mut text: Option<String> = None;
        let mut line = 0;
        for field in Fields::new(bytes) {
            let (number, value) = field?;
            match number {
                // A oneof: the last one set wins, as in protobuf.
                NODE_ELEMENT => {
                    element = Some(value.bytes()?);
                    text = None;
                }
                NODE_TEXT => {
                    text = Some(value.string()?.to_owned());
                    element = None;
                }
                NODE_SOURCE => line = source_line(value.bytes()?)?,
                _ => {}
            }
        }
        if let Some(text) = text {
            return Ok(Some(XmlNode::Text(text)));
        }
        let Some(element) = element else {
            return Ok(None);
        };
        if depth >= MAX_DEPTH {
            self.anomalies.push(XmlAnomaly {
                kind: XmlAnomalyKind::DepthLimitReached,
                offset: self.offset(element),
            });
            return Ok(None);
        }
        self.element(element, line, depth)
            .map(|element| Some(XmlNode::Element(element)))
    }

    fn element(
        &mut self,
        bytes: &[u8],
        line: u32,
        depth: usize,
    ) -> Result<XmlElement, ProtoProblem> {
        let mut element = XmlElement {
            namespace: None,
            name: String::new(),
            attributes: Vec::new(),
            children: Vec::new(),
            line,
        };
        for field in Fields::new(bytes) {
            let (number, value) = field?;
            match number {
                ELEMENT_NAMESPACE_DECLARATION => {
                    let namespace = namespace(value.bytes()?)?;
                    self.namespaces.push(namespace);
                }
                ELEMENT_NAMESPACE_URI => element.namespace = non_empty(value.string()?),
                ELEMENT_NAME => element.name = value.string()?.to_owned(),
                ELEMENT_ATTRIBUTE => {
                    let bytes = value.bytes()?;
                    let attribute = attribute(bytes)?;
                    if let Some(kind) = attribute_identity_anomaly(&attribute) {
                        self.anomalies.push(XmlAnomaly {
                            kind,
                            offset: self.offset(bytes),
                        });
                    }
                    element.attributes.push(attribute);
                }
                ELEMENT_CHILD => {
                    if let Some(child) = self.node(value.bytes()?, depth + 1)? {
                        element.children.push(child);
                    }
                }
                _ => {}
            }
        }
        Ok(element)
    }
}

fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}

fn source_line(bytes: &[u8]) -> Result<u32, ProtoProblem> {
    let mut line = 0;
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        if number == SOURCE_LINE {
            line = value.uint32()?;
        }
    }
    Ok(line)
}

fn namespace(bytes: &[u8]) -> Result<Namespace, ProtoProblem> {
    let mut namespace = Namespace {
        prefix: None,
        uri: String::new(),
        line: 0,
    };
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        match number {
            NAMESPACE_PREFIX => namespace.prefix = non_empty(value.string()?),
            NAMESPACE_URI => namespace.uri = value.string()?.to_owned(),
            NAMESPACE_SOURCE => namespace.line = source_line(value.bytes()?)?,
            _ => {}
        }
    }
    Ok(namespace)
}

/// An attribute: its compiled value when aapt2 compiled one, else its text as a string, the
/// way binary XML stores uncompiled attributes.
fn attribute(bytes: &[u8]) -> Result<XmlAttribute, ProtoProblem> {
    let mut namespace = None;
    let mut name = String::new();
    let mut text = String::new();
    let mut resource_id = None;
    let mut compiled = None;
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        match number {
            ATTRIBUTE_NAMESPACE_URI => namespace = non_empty(value.string()?),
            ATTRIBUTE_NAME => name = value.string()?.to_owned(),
            ATTRIBUTE_VALUE => text = value.string()?.to_owned(),
            // 0 is "no resource ID", as in the binary resource map.
            ATTRIBUTE_RESOURCE_ID => resource_id = Some(value.uint32()?).filter(|id| *id != 0),
            ATTRIBUTE_COMPILED_ITEM => compiled = item(value.bytes()?)?,
            _ => {}
        }
    }
    let value = compiled.unwrap_or_else(|| Value::String(Some(text.clone())));
    Ok(XmlAttribute {
        namespace,
        name,
        resource_id,
        value,
        raw: non_empty(&text),
    })
}

/// An `Item` (shared with the protobuf resource table); `None` when none of its values is set.
pub(super) fn item(bytes: &[u8]) -> Result<Option<Value>, ProtoProblem> {
    let mut value = None;
    for field in Fields::new(bytes) {
        let (number, field) = field?;
        let decoded = match number {
            ITEM_REFERENCE => reference(field.bytes()?)?,
            ITEM_STRING | ITEM_RAW_STRING | ITEM_STYLED_STRING | ITEM_FILE => {
                Value::String(Some(text_value(field.bytes()?)?))
            }
            // aapt2 flattens an `@+id` value to a false boolean.
            ITEM_ID => Value::Boolean(false),
            ITEM_PRIMITIVE => match primitive(field.bytes()?)? {
                Some(primitive) => primitive,
                None => continue,
            },
            _ => continue,
        };
        // A oneof: the last one set wins.
        value = Some(decoded);
    }
    Ok(value)
}

fn reference(bytes: &[u8]) -> Result<Value, ProtoProblem> {
    let mut is_attribute = false;
    let mut id = 0;
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        match number {
            REFERENCE_TYPE => is_attribute = value.varint()? == REFERENCE_TYPE_ATTRIBUTE,
            REFERENCE_ID => id = value.uint32()?,
            _ => {}
        }
    }
    Ok(if is_attribute {
        Value::Attribute(id)
    } else {
        Value::Reference(id)
    })
}

fn text_value(bytes: &[u8]) -> Result<String, ProtoProblem> {
    let mut text = String::new();
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        if number == TEXT_VALUE {
            text = value.string()?.to_owned();
        }
    }
    Ok(text)
}

/// A `Primitive`; `None` when no value is set (or only a deprecated float form).
fn primitive(bytes: &[u8]) -> Result<Option<Value>, ProtoProblem> {
    let mut value = None;
    for field in Fields::new(bytes) {
        let (number, field) = field?;
        let decoded = match number {
            1 => Value::Null,
            2 => Value::Empty,
            3 => Value::Float(field.float()?),
            // int32: negative values arrive sign-extended to 64 bits.
            6 => Value::Integer(field.varint()? as i64 as i32),
            7 => Value::Hex(field.uint32()?),
            8 => Value::Boolean(field.varint()? != 0),
            9..=12 => Value::Color(field.uint32()?),
            13 => Value::decode(TYPE_DIMENSION, field.uint32()?, |_| None),
            14 => Value::decode(TYPE_FRACTION, field.uint32()?, |_| None),
            // 4 and 5: deprecated float dimensions and fractions without a unit; aapt2 no
            // longer writes them.
            _ => continue,
        };
        value = Some(decoded);
    }
    Ok(value)
}
