//! Android binary XML (`AndroidManifest.xml` and compiled `res/xml` files), decoded the way the
//! platform's `ResXMLTree` and `ResXMLParser` read it.
//!
//! Where Android and name-based tools disagree, msec follows Android and reports the
//! difference as an anomaly. The main case: Android identifies `android:` attributes by the
//! resource ID in the resource map, never by the name string, so obfuscators rename or blank the
//! name strings to mislead tools that read names.

use std::fmt::Write as _;

use super::chunk::{
    CHUNK_HEADER_LENGTH, Chunk, ChunkProblem, RES_STRING_POOL_TYPE, RES_XML_CDATA_TYPE,
    RES_XML_END_ELEMENT_TYPE, RES_XML_END_NAMESPACE_TYPE, RES_XML_FIRST_CHUNK_TYPE,
    RES_XML_LAST_CHUNK_TYPE, RES_XML_RESOURCE_MAP_TYPE, RES_XML_START_ELEMENT_TYPE,
    RES_XML_START_NAMESPACE_TYPE, RES_XML_TYPE, u16_at, u32_at,
};
use super::generated::attributes::FRAMEWORK_ATTRIBUTES;
use super::string_pool::{StringPool, StringPoolProblem};
use super::value::Value;

/// Namespace URI of `android:` attributes.
pub const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";

/// `ResXMLTree_node`: chunk header, line number, comment index.
const NODE_HEADER_LENGTH: usize = 16;
/// `ResXMLTree_attribute`: namespace, name, raw value, `Res_value`.
const ATTRIBUTE_LENGTH: usize = 20;
/// `ResXMLTree_attrExt` up to and including the attribute count.
const START_ELEMENT_EXTENSION_LENGTH: usize = 20;
const NO_STRING: u32 = u32::MAX;
/// Deeper elements are skipped. Real manifests nest about six levels.
const MAX_DEPTH: usize = 256;

/// A decoded binary XML document.
#[derive(Debug, Clone, PartialEq)]
pub struct XmlDocument {
    /// The first top-level element. `None` when the file has no elements.
    pub root: Option<XmlElement>,
    /// Namespace declarations, in document order.
    pub namespaces: Vec<Namespace>,
    /// Structural oddities, in document order.
    pub anomalies: Vec<XmlAnomaly>,
}

/// A namespace declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    /// The prefix (`android`), when declared with one.
    pub prefix: Option<String>,
    /// The URI.
    pub uri: String,
    /// Line number recorded by the compiler.
    pub line: u32,
}

/// An element.
#[derive(Debug, Clone, PartialEq)]
pub struct XmlElement {
    /// Namespace URI, when the element has one.
    pub namespace: Option<String>,
    /// Element name.
    pub name: String,
    /// Attributes, in file order.
    pub attributes: Vec<XmlAttribute>,
    /// Child elements and text, in file order.
    pub children: Vec<XmlNode>,
    /// Line number recorded by the compiler.
    pub line: u32,
}

/// A child of an element.
#[derive(Debug, Clone, PartialEq)]
pub enum XmlNode {
    /// A child element.
    Element(XmlElement),
    /// Character data.
    Text(String),
}

/// An attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct XmlAttribute {
    /// Namespace URI, when the attribute has one.
    pub namespace: Option<String>,
    /// The name string from the string pool. For `android:` attributes this may be altered by
    /// obfuscators; [`XmlAttribute::display_name`] gives the name Android resolves.
    pub name: String,
    /// Resource ID from the resource map. Android matches `android:` attributes by this alone.
    pub resource_id: Option<u32>,
    /// The typed value Android reads.
    pub value: Value,
    /// The raw string the compiler kept (`rawValue`), when there is one. Android reads
    /// [`XmlAttribute::value`]; some tools show this.
    pub raw: Option<String>,
}

impl XmlAttribute {
    /// The framework name for the resource ID when it has one, else the name string.
    pub fn display_name(&self) -> &str {
        self.resource_id
            .and_then(framework_attribute_name)
            .unwrap_or(&self.name)
    }
}

impl XmlElement {
    /// The value of the attribute with this resource ID, as Android resolves `android:`
    /// attributes. An attribute without a resource ID never matches.
    pub fn attribute(&self, resource_id: u32) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|attribute| attribute.resource_id == Some(resource_id))
            .map(|attribute| &attribute.value)
    }

    /// The value of an attribute without namespace, by name (Android reads `package` and
    /// `platformBuildVersionCode` this way).
    pub fn plain_attribute(&self, name: &str) -> Option<&Value> {
        self.attributes
            .iter()
            .find(|attribute| attribute.namespace.is_none() && attribute.name == name)
            .map(|attribute| &attribute.value)
    }

    /// Child elements.
    pub fn elements(&self) -> impl Iterator<Item = &XmlElement> {
        self.children.iter().filter_map(|child| match child {
            XmlNode::Element(element) => Some(element),
            XmlNode::Text(_) => None,
        })
    }

    /// Child elements with this name.
    pub fn elements_named<'element>(
        &'element self,
        name: &'element str,
    ) -> impl Iterator<Item = &'element XmlElement> {
        self.elements().filter(move |element| element.name == name)
    }
}

/// A structural oddity, with the byte offset of the chunk where it was found.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XmlAnomaly {
    /// What was found.
    pub kind: XmlAnomalyKind,
    /// Byte offset in the file.
    pub offset: usize,
}

/// What kind of oddity was found in a binary XML file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum XmlAnomalyKind {
    /// The file declares a size larger than it is. Android rejects it.
    DeclaredSizePastEnd,
    /// Bytes after the declared end of the document.
    TrailingBytes {
        /// How many.
        bytes: usize,
    },
    /// A chunk size is not a multiple of four. Android rejects the file.
    Misaligned,
    /// More than one string pool. Android uses the last one; tools that take the first see
    /// different strings.
    MultipleStringPools,
    /// More than one resource map. Android uses the last one.
    MultipleResourceMaps,
    /// A chunk type Android does not know. Android skips it.
    UnknownChunk {
        /// The chunk type.
        kind: u16,
    },
    /// A node whose header or attribute layout is invalid. Android stops reading the document
    /// here and rejects it.
    MalformedNode(MalformedNode),
    /// No element at all. Android rejects the document.
    NoElements,
    /// A string index outside the string pool.
    InvalidStringReference,
    /// The name string of a framework attribute differs from the name of its resource ID
    /// (obfuscation: Android uses the ID).
    AttributeNameMismatch {
        /// Name of the resource ID, which Android uses.
        resolved: String,
        /// Name in the string pool, which name-based tools show.
        written: String,
    },
    /// An `android:` attribute without a resource ID. Android ignores it; name-based tools do
    /// not.
    UnresolvedAndroidAttribute {
        /// The attribute name.
        name: String,
    },
    /// An end tag that does not match the open element.
    MismatchedEndTag {
        /// The open element.
        open: String,
        /// The end tag.
        closed: String,
    },
    /// An element that is never closed.
    UnclosedElement {
        /// The element name.
        name: String,
    },
    /// More than one top-level element; only the first is the document root.
    MultipleRootElements,
    /// Elements nested deeper than msec follows were skipped.
    DepthLimitReached,
}

/// How a node is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MalformedNode {
    /// The chunk header is invalid.
    Chunk(ChunkProblem),
    /// The node is too short for its type.
    TooShort,
    /// Attributes extend past the node.
    AttributesOutOfBounds,
}

impl XmlAnomalyKind {
    /// True when Android refuses the document (for a manifest: the package does not install).
    pub fn rejected_by_android(&self) -> bool {
        matches!(
            self,
            Self::DeclaredSizePastEnd
                | Self::Misaligned
                | Self::MalformedNode(_)
                | Self::NoElements
        )
    }
}

/// Why a file cannot be decoded at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlError {
    /// The file is not binary XML (for example plain-text XML, as in AARs).
    NotBinaryXml,
    /// The document header is invalid.
    Chunk(ChunkProblem),
    /// No string pool before the first element.
    NoStringPool,
    /// The string pool is invalid.
    StringPool(StringPoolProblem),
}

impl std::fmt::Display for XmlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotBinaryXml => write!(formatter, "not an Android binary XML file"),
            Self::Chunk(problem) => write!(formatter, "invalid document header: {problem:?}"),
            Self::NoStringPool => write!(formatter, "no string pool"),
            Self::StringPool(problem) => write!(formatter, "invalid string pool: {problem:?}"),
        }
    }
}

impl std::error::Error for XmlError {}

/// Decodes a binary XML file.
pub fn parse(bytes: &[u8]) -> Result<XmlDocument, XmlError> {
    let mut anomalies = Vec::new();
    let end = document_end(bytes, &mut anomalies)?;
    let header_size =
        usize::from(u16_at(bytes, 2).ok_or(XmlError::Chunk(ChunkProblem::Truncated))?);
    let prologue = read_prologue(bytes, header_size, end, &mut anomalies)?;
    let mut reader = NodeReader {
        bytes,
        end,
        prologue: &prologue,
        anomalies,
        misaligned_reported: false,
    };
    let mut builder = TreeBuilder::default();
    if let Some(first_node) = prologue.first_node {
        reader.read_nodes(first_node, &mut builder);
    }
    let mut anomalies = reader.anomalies;
    let (root, namespaces) = builder.finish(&mut anomalies, end);
    Ok(XmlDocument {
        root,
        namespaces,
        anomalies,
    })
}

/// Validates the outer `RES_XML_TYPE` chunk and returns where the document ends.
fn document_end(bytes: &[u8], anomalies: &mut Vec<XmlAnomaly>) -> Result<usize, XmlError> {
    let kind = u16_at(bytes, 0).ok_or(XmlError::NotBinaryXml)?;
    if kind != RES_XML_TYPE {
        return Err(XmlError::NotBinaryXml);
    }
    let header_size =
        usize::from(u16_at(bytes, 2).ok_or(XmlError::Chunk(ChunkProblem::Truncated))?);
    let declared = u32_at(bytes, 4).ok_or(XmlError::Chunk(ChunkProblem::Truncated))? as usize;
    if header_size < CHUNK_HEADER_LENGTH {
        return Err(XmlError::Chunk(ChunkProblem::HeaderTooSmall));
    }
    if declared < header_size {
        return Err(XmlError::Chunk(ChunkProblem::SizeSmallerThanHeader));
    }
    if declared > bytes.len() {
        anomalies.push(XmlAnomaly {
            kind: XmlAnomalyKind::DeclaredSizePastEnd,
            offset: 0,
        });
        return Ok(bytes.len());
    }
    if declared < bytes.len() {
        anomalies.push(XmlAnomaly {
            kind: XmlAnomalyKind::TrailingBytes {
                bytes: bytes.len() - declared,
            },
            offset: declared,
        });
    }
    Ok(declared)
}

/// String pool, resource map and where the nodes start.
struct Prologue {
    strings: StringPool,
    /// Absolute start and entry count of the resource map.
    resource_map: Option<(usize, usize)>,
    first_node: Option<usize>,
}

/// Reads the chunks before the first node, as `ResXMLTree::setTo` does: the last string pool
/// and the last resource map win, unknown chunks are skipped.
fn read_prologue(
    bytes: &[u8],
    header_size: usize,
    end: usize,
    anomalies: &mut Vec<XmlAnomaly>,
) -> Result<Prologue, XmlError> {
    let mut strings = None;
    let mut resource_map = None;
    let mut position = header_size;
    while position + CHUNK_HEADER_LENGTH <= end {
        let chunk =
            Chunk::read(bytes, position, end, CHUNK_HEADER_LENGTH).map_err(XmlError::Chunk)?;
        if !chunk.is_aligned() {
            anomalies.push(XmlAnomaly {
                kind: XmlAnomalyKind::Misaligned,
                offset: position,
            });
        }
        match chunk.kind {
            RES_STRING_POOL_TYPE => {
                if strings.is_some() {
                    anomalies.push(XmlAnomaly {
                        kind: XmlAnomalyKind::MultipleStringPools,
                        offset: position,
                    });
                }
                strings = Some(StringPool::parse(&chunk).map_err(XmlError::StringPool)?);
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                if resource_map.is_some() {
                    anomalies.push(XmlAnomaly {
                        kind: XmlAnomalyKind::MultipleResourceMaps,
                        offset: position,
                    });
                }
                let count = (chunk.bytes.len() - chunk.header_size) / 4;
                resource_map = Some((chunk.offset + chunk.header_size, count));
            }
            RES_XML_FIRST_CHUNK_TYPE..=RES_XML_LAST_CHUNK_TYPE => {
                let strings = strings.ok_or(XmlError::NoStringPool)?;
                return Ok(Prologue {
                    strings,
                    resource_map,
                    first_node: Some(position),
                });
            }
            kind => anomalies.push(XmlAnomaly {
                kind: XmlAnomalyKind::UnknownChunk { kind },
                offset: position,
            }),
        }
        position = chunk.end();
    }
    let strings = strings.ok_or(XmlError::NoStringPool)?;
    Ok(Prologue {
        strings,
        resource_map,
        first_node: None,
    })
}

/// Walks the node chunks, as `ResXMLParser::nextNode` does.
struct NodeReader<'data> {
    bytes: &'data [u8],
    end: usize,
    prologue: &'data Prologue,
    anomalies: Vec<XmlAnomaly>,
    misaligned_reported: bool,
}

impl NodeReader<'_> {
    fn read_nodes(&mut self, first_node: usize, builder: &mut TreeBuilder) {
        let mut position = first_node;
        while position < self.end {
            let chunk = match Chunk::read(self.bytes, position, self.end, NODE_HEADER_LENGTH) {
                Ok(chunk) => chunk,
                Err(problem) => {
                    self.anomaly(
                        XmlAnomalyKind::MalformedNode(MalformedNode::Chunk(problem)),
                        position,
                    );
                    return;
                }
            };
            if !chunk.is_aligned() && !self.misaligned_reported {
                self.misaligned_reported = true;
                self.anomaly(XmlAnomalyKind::Misaligned, position);
            }
            if let Err(problem) = self.read_node(&chunk, builder) {
                self.anomaly(XmlAnomalyKind::MalformedNode(problem), position);
                return;
            }
            position = chunk.end();
        }
    }

    fn read_node(
        &mut self,
        chunk: &Chunk<'_>,
        builder: &mut TreeBuilder,
    ) -> Result<(), MalformedNode> {
        let extension = &chunk.bytes[chunk.header_size..];
        let line = chunk.u32_at(8).unwrap_or(0);
        let needs = |length: usize| {
            if extension.len() < length {
                Err(MalformedNode::TooShort)
            } else {
                Ok(())
            }
        };
        match chunk.kind {
            RES_XML_START_NAMESPACE_TYPE => {
                needs(8)?;
                let prefix = self.optional_string(u32_at(extension, 0), chunk.offset);
                let uri = self
                    .optional_string(u32_at(extension, 4), chunk.offset)
                    .unwrap_or_default();
                builder.namespaces.push(Namespace { prefix, uri, line });
            }
            RES_XML_END_NAMESPACE_TYPE => needs(8)?,
            RES_XML_START_ELEMENT_TYPE => {
                needs(START_ELEMENT_EXTENSION_LENGTH)?;
                let element = self.read_start_element(chunk, extension, line)?;
                builder.open(element, &mut self.anomalies, chunk.offset);
            }
            RES_XML_END_ELEMENT_TYPE => {
                needs(8)?;
                let name = self
                    .optional_string(u32_at(extension, 4), chunk.offset)
                    .unwrap_or_default();
                builder.close(&name, &mut self.anomalies, chunk.offset);
            }
            RES_XML_CDATA_TYPE => {
                needs(12)?;
                if let Some(text) = self.optional_string(u32_at(extension, 0), chunk.offset) {
                    builder.text(text);
                }
            }
            kind => self.anomaly(XmlAnomalyKind::UnknownChunk { kind }, chunk.offset),
        }
        Ok(())
    }

    fn read_start_element(
        &mut self,
        chunk: &Chunk<'_>,
        extension: &[u8],
        line: u32,
    ) -> Result<XmlElement, MalformedNode> {
        let field = |offset| {
            u16_at(extension, offset)
                .map(usize::from)
                .ok_or(MalformedNode::TooShort)
        };
        let (attribute_start, attribute_size, attribute_count) =
            (field(8)?, field(10)?, field(12)?);
        // validateNode: the declared attribute block must fit in the node.
        let block_end = attribute_size
            .checked_mul(attribute_count)
            .and_then(|length| length.checked_add(attribute_start))
            .ok_or(MalformedNode::AttributesOutOfBounds)?;
        if block_end > extension.len() {
            return Err(MalformedNode::AttributesOutOfBounds);
        }
        let mut attributes = Vec::with_capacity(attribute_count);
        for index in 0..attribute_count {
            let start = attribute_start + index * attribute_size;
            let raw = extension
                .get(start..start + ATTRIBUTE_LENGTH)
                .ok_or(MalformedNode::AttributesOutOfBounds)?;
            attributes.push(self.read_attribute(raw, chunk.offset));
        }
        Ok(XmlElement {
            namespace: self.optional_string(u32_at(extension, 0), chunk.offset),
            name: self
                .optional_string(u32_at(extension, 4), chunk.offset)
                .unwrap_or_default(),
            attributes,
            children: Vec::new(),
            line,
        })
    }

    fn read_attribute(&mut self, raw: &[u8], offset: usize) -> XmlAttribute {
        let name_index = u32_at(raw, 4).unwrap_or(NO_STRING);
        let namespace = self.optional_string(u32_at(raw, 0), offset);
        let name = self
            .optional_string(Some(name_index), offset)
            .unwrap_or_default();
        let resource_id = self.resource_id(name_index);
        let raw_value = self.optional_string(u32_at(raw, 8), offset);
        let data_type = raw[15];
        let data = u32_at(raw, 16).unwrap_or(0);
        let value = Value::decode(data_type, data, |index| {
            self.prologue.strings.get(self.bytes, index)
        });
        if matches!(value, Value::String(None)) {
            self.anomaly(XmlAnomalyKind::InvalidStringReference, offset);
        }
        let attribute = XmlAttribute {
            namespace,
            name,
            resource_id,
            value,
            raw: raw_value,
        };
        self.check_attribute_identity(&attribute, offset);
        attribute
    }

    /// Flags attributes whose name string and resource ID tell different stories.
    fn check_attribute_identity(&mut self, attribute: &XmlAttribute, offset: usize) {
        match attribute.resource_id.and_then(framework_attribute_name) {
            Some(resolved) if resolved != attribute.name => self.anomaly(
                XmlAnomalyKind::AttributeNameMismatch {
                    resolved: resolved.to_owned(),
                    written: attribute.name.clone(),
                },
                offset,
            ),
            Some(_) => {}
            None => {
                let is_android = attribute.namespace.as_deref() == Some(ANDROID_NAMESPACE);
                if is_android
                    && attribute.resource_id.is_none()
                    && framework_attribute_id(&attribute.name).is_some()
                {
                    self.anomaly(
                        XmlAnomalyKind::UnresolvedAndroidAttribute {
                            name: attribute.name.clone(),
                        },
                        offset,
                    );
                }
            }
        }
    }

    /// `ResXMLParser::getAttributeNameResID`: the resource map is indexed by the name's string
    /// index.
    fn resource_id(&self, name_index: u32) -> Option<u32> {
        let (start, count) = self.prologue.resource_map?;
        let index = name_index as usize;
        if index >= count {
            return None;
        }
        u32_at(self.bytes, start + index * 4).filter(|&id| id != 0)
    }

    /// The string at `index`; `None` for the "no string" marker. Records out-of-range indices.
    fn optional_string(&mut self, index: Option<u32>, offset: usize) -> Option<String> {
        let index = index.filter(|&index| index != NO_STRING)?;
        let string = self.prologue.strings.get(self.bytes, index);
        if string.is_none() {
            self.anomaly(XmlAnomalyKind::InvalidStringReference, offset);
        }
        string
    }

    fn anomaly(&mut self, kind: XmlAnomalyKind, offset: usize) {
        self.anomalies.push(XmlAnomaly { kind, offset });
    }
}

/// Builds the element tree from start/end events, tolerating bad nesting.
#[derive(Default)]
struct TreeBuilder {
    open: Vec<XmlElement>,
    roots: Vec<XmlElement>,
    namespaces: Vec<Namespace>,
    /// Elements skipped below the depth limit that still await their end tag.
    skipped_depth: usize,
}

impl TreeBuilder {
    fn open(&mut self, element: XmlElement, anomalies: &mut Vec<XmlAnomaly>, offset: usize) {
        if self.open.len() >= MAX_DEPTH || self.skipped_depth > 0 {
            if self.skipped_depth == 0 {
                anomalies.push(XmlAnomaly {
                    kind: XmlAnomalyKind::DepthLimitReached,
                    offset,
                });
            }
            self.skipped_depth += 1;
            return;
        }
        self.open.push(element);
    }

    fn close(&mut self, name: &str, anomalies: &mut Vec<XmlAnomaly>, offset: usize) {
        if self.skipped_depth > 0 {
            self.skipped_depth -= 1;
            return;
        }
        let Some(element) = self.open.pop() else {
            return;
        };
        if element.name != name {
            anomalies.push(XmlAnomaly {
                kind: XmlAnomalyKind::MismatchedEndTag {
                    open: element.name.clone(),
                    closed: name.to_owned(),
                },
                offset,
            });
        }
        self.attach(element);
    }

    fn text(&mut self, text: String) {
        if let Some(parent) = self.open.last_mut() {
            parent.children.push(XmlNode::Text(text));
        }
    }

    fn attach(&mut self, element: XmlElement) {
        match self.open.last_mut() {
            Some(parent) => parent.children.push(XmlNode::Element(element)),
            None => self.roots.push(element),
        }
    }

    fn finish(
        mut self,
        anomalies: &mut Vec<XmlAnomaly>,
        end: usize,
    ) -> (Option<XmlElement>, Vec<Namespace>) {
        while let Some(element) = self.open.pop() {
            anomalies.push(XmlAnomaly {
                kind: XmlAnomalyKind::UnclosedElement {
                    name: element.name.clone(),
                },
                offset: end,
            });
            self.attach(element);
        }
        if self.roots.len() > 1 {
            anomalies.push(XmlAnomaly {
                kind: XmlAnomalyKind::MultipleRootElements,
                offset: end,
            });
        }
        if self.roots.is_empty() {
            anomalies.push(XmlAnomaly {
                kind: XmlAnomalyKind::NoElements,
                offset: end,
            });
        }
        (self.roots.into_iter().next(), self.namespaces)
    }
}

/// Name of a framework attribute resource ID (`0x01010001` is `label`).
pub fn framework_attribute_name(resource_id: u32) -> Option<&'static str> {
    FRAMEWORK_ATTRIBUTES
        .binary_search_by_key(&resource_id, |(id, _)| *id)
        .ok()
        .map(|index| FRAMEWORK_ATTRIBUTES[index].1)
}

/// Resource ID of a framework attribute name.
pub(crate) fn framework_attribute_id(name: &str) -> Option<u32> {
    FRAMEWORK_ATTRIBUTES
        .iter()
        .find(|(_, attribute)| *attribute == name)
        .map(|(id, _)| *id)
}

impl XmlDocument {
    /// The document as indented text XML, with `android:` attributes named the way Android
    /// resolves them. Values use the notation of `aapt2 dump xmltree` (`@0x7f0a0001` for
    /// references).
    pub fn to_xml(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        if let Some(root) = &self.root {
            write_element(&mut out, root, &self.namespaces, 0, true);
        }
        out
    }
}

fn write_element(
    out: &mut String,
    element: &XmlElement,
    namespaces: &[Namespace],
    depth: usize,
    is_root: bool,
) {
    let indent = "  ".repeat(depth);
    let _ = write!(
        out,
        "{indent}<{}",
        qualified(element.namespace.as_deref(), &element.name, namespaces)
    );
    if is_root {
        for namespace in namespaces {
            match &namespace.prefix {
                Some(prefix) => {
                    let _ = write!(out, " xmlns:{prefix}=\"{}\"", escape(&namespace.uri));
                }
                None => {
                    let _ = write!(out, " xmlns=\"{}\"", escape(&namespace.uri));
                }
            }
        }
    }
    for attribute in &element.attributes {
        let name = qualified(
            attribute.namespace.as_deref(),
            attribute.display_name(),
            namespaces,
        );
        let _ = write!(out, " {name}=\"{}\"", escape(&attribute.value.to_string()));
    }
    if element.children.is_empty() {
        out.push_str("/>\n");
        return;
    }
    out.push_str(">\n");
    for child in &element.children {
        match child {
            XmlNode::Element(child) => write_element(out, child, namespaces, depth + 1, false),
            XmlNode::Text(text) => {
                let _ = writeln!(out, "{indent}  {}", escape(text.trim()));
            }
        }
    }
    let _ = writeln!(
        out,
        "{indent}</{}>",
        qualified(element.namespace.as_deref(), &element.name, namespaces)
    );
}

fn qualified(namespace: Option<&str>, name: &str, namespaces: &[Namespace]) -> String {
    let prefix = namespace.and_then(|uri| {
        namespaces
            .iter()
            .find(|declared| declared.uri == uri)
            .and_then(|declared| declared.prefix.clone())
            .or_else(|| (uri == ANDROID_NAMESPACE).then(|| "android".to_owned()))
    });
    match prefix {
        Some(prefix) => format!("{prefix}:{name}"),
        None => name.to_owned(),
    }
}

/// XML escaping; control characters become `\u{fffd}` so the output is always well-formed.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\n' | '\t' => escaped.push(character),
            control if control.is_control() => escaped.push('\u{fffd}'),
            other => escaped.push(other),
        }
    }
    escaped
}
