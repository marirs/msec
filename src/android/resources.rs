//! `resources.arsc`: the compiled resource table, read the way AOSP `ResTable` reads it.
//!
//! The table is indexed once (packages, type chunks and their configurations); entries are
//! decoded on demand. Malformed packages or type chunks are skipped and reported, so one bad
//! chunk does not hide the rest of the table.

use std::collections::BTreeSet;
use std::fmt;

use super::chunk::{
    CHUNK_HEADER_LENGTH, Chunk, ChunkProblem, RES_STRING_POOL_TYPE, RES_TABLE_PACKAGE_TYPE,
    RES_TABLE_TYPE, RES_TABLE_TYPE_TYPE, u16_at, u32_at,
};
use super::proto::ProtoProblem;
use super::string_pool::{StringPool, StringPoolProblem};
use super::value::Value;

const TABLE_HEADER_LENGTH: usize = 12;
/// `ResTable_package` before `typeIdOffset` was added.
const PACKAGE_MIN_HEADER_LENGTH: usize = 284;
const PACKAGE_NAME_OFFSET: usize = 12;
const PACKAGE_NAME_UNITS: usize = 128;
/// `ResTable_type` up to the start of its `ResTable_config`.
const TYPE_HEADER_FIXED_LENGTH: usize = 20;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
const RES_TABLE_LIBRARY_TYPE: u16 = 0x0203;
const RES_TABLE_OVERLAYABLE_TYPE: u16 = 0x0204;
const RES_TABLE_OVERLAYABLE_POLICY_TYPE: u16 = 0x0205;
const RES_TABLE_STAGED_ALIAS_TYPE: u16 = 0x0206;

const TYPE_FLAG_SPARSE: u8 = 0x01;
const TYPE_FLAG_OFFSET16: u8 = 0x02;
const NO_ENTRY_32: u32 = u32::MAX;
const NO_ENTRY_16: u16 = u16::MAX;

const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
const ENTRY_FLAG_COMPACT: u16 = 0x0008;
const MAP_ITEM_LENGTH: usize = 12;
/// Reference chains longer than this are treated as cycles.
const MAX_REFERENCE_DEPTH: usize = 8;

/// Why a resource table cannot be read at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// The file does not start with a `RES_TABLE_TYPE` chunk.
    NotResourceTable,
    /// The table header is invalid.
    Chunk(ChunkProblem),
    /// The global string pool is invalid.
    StringPool(StringPoolProblem),
    /// A protobuf table (`resources.pb`) that protobuf's own parser rejects.
    InvalidProtobuf(ProtoProblem),
}

impl fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotResourceTable => write!(formatter, "not an Android resource table"),
            Self::Chunk(problem) => write!(formatter, "invalid resource table header: {problem:?}"),
            Self::StringPool(problem) => write!(formatter, "invalid string pool: {problem:?}"),
            Self::InvalidProtobuf(problem) => {
                write!(formatter, "invalid protobuf resource table: {problem:?}")
            }
        }
    }
}

impl std::error::Error for ResourceError {}

/// A structural oddity in the resource table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceAnomaly {
    /// What was found.
    pub kind: ResourceAnomalyKind,
    /// Byte offset in the table.
    pub offset: usize,
}

/// What kind of oddity was found in a resource table.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceAnomalyKind {
    /// A chunk header is invalid; the rest of its container was skipped.
    MalformedChunk(ChunkProblem),
    /// A chunk size is not a multiple of four. Android rejects the table.
    Misaligned,
    /// A chunk type Android does not know.
    UnknownChunk {
        /// The chunk type.
        kind: u16,
    },
    /// A package chunk whose header or string pools are invalid; it was skipped.
    MalformedPackage,
    /// A type chunk whose entry offsets do not fit; it was skipped.
    MalformedTypeChunk,
    /// The header's package count differs from the packages found.
    PackageCountMismatch {
        /// Count in the header.
        declared: u32,
        /// Packages found.
        found: usize,
    },
}

impl ResourceAnomalyKind {
    /// True when Android's `ResTable` refuses the table (its chunk validation fails).
    pub fn rejected_by_android(&self) -> bool {
        matches!(self, Self::MalformedChunk(_) | Self::Misaligned)
    }
}

/// A resource configuration (qualifiers such as locale, density and SDK level).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Config {
    /// `ResTable_config` as stored, zero-padded to the fields msec reads.
    bytes: Vec<u8>,
}

/// Fields msec reads end at `screenLayout2` (offset 48); 64 covers them with room.
const CONFIG_READ_LENGTH: usize = 64;

impl Config {
    pub(super) fn from_bytes(raw: &[u8]) -> Self {
        let mut bytes = raw[..raw.len().min(CONFIG_READ_LENGTH)].to_vec();
        bytes.resize(CONFIG_READ_LENGTH, 0);
        Self { bytes }
    }

    fn u8_at(&self, offset: usize) -> u8 {
        self.bytes[offset]
    }

    fn u16_at(&self, offset: usize) -> u16 {
        u16_at(&self.bytes, offset).unwrap_or(0)
    }

    /// True for the default configuration (no qualifiers).
    pub fn is_default(&self) -> bool {
        self.bytes[4..].iter().all(|&byte| byte == 0)
    }

    /// Language code (`en`, `fil`), when set.
    pub fn language(&self) -> Option<String> {
        unpack_language_or_region([self.u8_at(8), self.u8_at(9)], b'a')
    }

    /// Region code (`US`, `419`), when set.
    pub fn region(&self) -> Option<String> {
        unpack_language_or_region([self.u8_at(10), self.u8_at(11)], b'0')
    }

    /// Script code (`Hant`), when set.
    pub fn script(&self) -> Option<String> {
        let script: String = self.bytes[36..40]
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| char::from(byte))
            .collect();
        (!script.is_empty() && script.chars().all(|c| c.is_ascii_alphabetic())).then_some(script)
    }

    /// BCP 47 locale (`en`, `en-GB`, `zh-Hant-TW`), when the configuration has a language.
    pub fn locale(&self) -> Option<String> {
        let mut locale = self.language()?;
        if let Some(script) = self.script() {
            locale.push('-');
            locale.push_str(&script);
        }
        if let Some(region) = self.region() {
            locale.push('-');
            locale.push_str(&region);
        }
        Some(locale)
    }

    /// Screen density in dpi; 0 when unset, `0xfffe` for anydpi, `0xffff` for nodpi.
    pub fn density(&self) -> u16 {
        self.u16_at(14)
    }

    /// Minimum SDK level qualifier (`-v26`); 0 when unset.
    pub fn sdk_version(&self) -> u16 {
        self.u16_at(24)
    }

    /// `Some(true)` for `-night`, `Some(false)` for `-notnight`.
    pub fn night_mode(&self) -> Option<bool> {
        match self.u8_at(29) & 0x30 {
            0x10 => Some(false),
            0x20 => Some(true),
            _ => None,
        }
    }

    /// Qualifier string in aapt2 notation (`de`, `en-rGB`, `xxhdpi-v26`), or `default`.
    pub fn qualifiers(&self) -> String {
        let mut parts = Vec::new();
        if let Some(language) = self.language() {
            match self.region() {
                Some(region) => parts.push(format!("{language}-r{region}")),
                None => parts.push(language),
            }
        }
        match self.night_mode() {
            Some(true) => parts.push("night".to_owned()),
            Some(false) => parts.push("notnight".to_owned()),
            None => {}
        }
        if let Some(density) = density_name(self.density()) {
            parts.push(density);
        }
        if self.sdk_version() > 0 {
            parts.push(format!("v{}", self.sdk_version()));
        }
        if parts.is_empty() && !self.is_default() {
            parts.push("other".to_owned());
        }
        if parts.is_empty() {
            "default".to_owned()
        } else {
            parts.join("-")
        }
    }
}

fn density_name(density: u16) -> Option<String> {
    Some(match density {
        0 => return None,
        120 => "ldpi".to_owned(),
        160 => "mdpi".to_owned(),
        213 => "tvdpi".to_owned(),
        240 => "hdpi".to_owned(),
        320 => "xhdpi".to_owned(),
        480 => "xxhdpi".to_owned(),
        640 => "xxxhdpi".to_owned(),
        0xfffe => "anydpi".to_owned(),
        0xffff => "nodpi".to_owned(),
        other => format!("{other}dpi"),
    })
}

/// Two-letter codes are stored as is; three-letter codes are packed into 15 bits.
fn unpack_language_or_region(packed: [u8; 2], base: u8) -> Option<String> {
    if packed[0] == 0 {
        return None;
    }
    let text = if packed[0] & 0x80 != 0 {
        let first = packed[1] & 0x1f;
        let second = ((packed[1] & 0xe0) >> 5) | ((packed[0] & 0x03) << 3);
        let third = (packed[0] & 0x7c) >> 2;
        [first, second, third]
            .iter()
            .map(|&code| char::from(code + base))
            .collect()
    } else {
        packed
            .iter()
            .map(|&byte| char::from(byte))
            .collect::<String>()
    };
    text.chars()
        .all(|c| c.is_ascii_alphanumeric())
        .then_some(text)
}

/// `package:type/entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceName {
    /// Package name.
    pub package: String,
    /// Type name (`string`, `xml`, `mipmap`).
    pub type_name: String,
    /// Entry name.
    pub entry: String,
}

impl fmt::Display for ResourceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}/{}",
            self.package, self.type_name, self.entry
        )
    }
}

/// The value of an entry in one configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum EntryValue {
    /// A single value.
    Simple(Value),
    /// A bag (style, array, plurals): parent and `(attribute or key, value)` items.
    Complex {
        /// Parent resource ID, 0 when none.
        parent: u32,
        /// Items.
        items: Vec<(u32, Value)>,
    },
}

/// One configuration of a resource.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceValue {
    /// The configuration.
    pub config: Config,
    /// The value in that configuration.
    pub value: EntryValue,
}

#[derive(Debug, Clone)]
struct Package {
    id: u32,
    name: String,
    type_names: StringPool,
    key_names: StringPool,
    type_id_offset: u32,
    types: Vec<TypeChunk>,
}

#[derive(Debug, Clone)]
struct TypeChunk {
    type_id: u8,
    flags: u8,
    entry_count: usize,
    /// Absolute positions in the table.
    offsets_start: usize,
    entries_start: usize,
    end: usize,
    config: Config,
}

/// A decoded resource table: `resources.arsc` from an APK, or `resources.pb` from an app bundle
/// ([`ResourceTable::parse_proto`]). Both answer the same questions the same way.
#[derive(Debug, Clone)]
pub struct ResourceTable {
    source: TableSource,
    anomalies: Vec<ResourceAnomaly>,
}

#[derive(Debug, Clone)]
enum TableSource {
    /// Binary `resources.arsc`, indexed once and decoded on demand.
    Arsc(ArscTable),
    /// aapt2's protobuf table, decoded whole (see [`super::proto_resources`]).
    Protobuf(super::proto_resources::ProtoTable),
}

/// The binary table: its bytes, global string pool and package index.
#[derive(Debug, Clone)]
struct ArscTable {
    bytes: Vec<u8>,
    strings: Option<StringPool>,
    packages: Vec<Package>,
}

impl ResourceTable {
    /// Indexes a resource table.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, ResourceError> {
        if u16_at(&bytes, 0) != Some(RES_TABLE_TYPE) {
            return Err(ResourceError::NotResourceTable);
        }
        let table = Chunk::read(&bytes, 0, bytes.len(), TABLE_HEADER_LENGTH)
            .map_err(ResourceError::Chunk)?;
        let declared_packages = table.u32_at(8).unwrap_or(0);
        let (end, header_size) = (table.end(), table.header_size);
        let mut index = TableIndex {
            bytes: &bytes,
            anomalies: Vec::new(),
            strings: None,
            packages: Vec::new(),
        };
        index.read_table_chunks(header_size, end)?;
        let TableIndex {
            mut anomalies,
            strings,
            packages,
            ..
        } = index;
        if packages.len() != declared_packages as usize {
            anomalies.push(ResourceAnomaly {
                kind: ResourceAnomalyKind::PackageCountMismatch {
                    declared: declared_packages,
                    found: packages.len(),
                },
                offset: 8,
            });
        }
        Ok(Self {
            source: TableSource::Arsc(ArscTable {
                bytes,
                strings,
                packages,
            }),
            anomalies,
        })
    }

    /// Decodes aapt2's protobuf resource table (`resources.pb` in an app bundle module).
    pub fn parse_proto(bytes: &[u8]) -> Result<Self, ResourceError> {
        let table = super::proto_resources::ProtoTable::parse(bytes)
            .map_err(ResourceError::InvalidProtobuf)?;
        Ok(Self {
            source: TableSource::Protobuf(table),
            anomalies: Vec::new(),
        })
    }

    /// Structural oddities found while indexing.
    pub fn anomalies(&self) -> &[ResourceAnomaly] {
        &self.anomalies
    }

    /// Package names, in table order.
    pub fn package_names(&self) -> Vec<String> {
        match &self.source {
            TableSource::Arsc(table) => table.package_names(),
            TableSource::Protobuf(table) => table.package_names(),
        }
    }

    /// `package:type/entry` for a resource ID.
    pub fn name(&self, id: u32) -> Option<ResourceName> {
        match &self.source {
            TableSource::Arsc(table) => table.name(id),
            TableSource::Protobuf(table) => table.name(id),
        }
    }

    /// Every configuration of a resource.
    pub fn values(&self, id: u32) -> Vec<ResourceValue> {
        match &self.source {
            TableSource::Arsc(table) => table.values(id),
            TableSource::Protobuf(table) => table.values(id),
        }
    }

    /// Resource ID of `type/entry` in the first package that has it.
    pub fn find(&self, type_name: &str, entry_name: &str) -> Option<u32> {
        match &self.source {
            TableSource::Arsc(table) => table.find(type_name, entry_name),
            TableSource::Protobuf(table) => table.find(type_name, entry_name),
        }
    }

    /// Resource IDs of every entry of a type (`string`), in package, type and entry order, each
    /// once.
    pub fn ids_of_type(&self, type_name: &str) -> Vec<u32> {
        match &self.source {
            TableSource::Arsc(table) => table.ids_of_type(type_name),
            TableSource::Protobuf(table) => table.ids_of_type(type_name),
        }
    }

    /// Locales the app's strings are translated into, sorted (`de`, `en-GB`, `ja`).
    pub fn locales(&self) -> Vec<String> {
        match &self.source {
            TableSource::Arsc(table) => table.locales(),
            TableSource::Protobuf(table) => table.locales(),
        }
    }

    /// The value for the default configuration (else English, else the first), following
    /// references. `None` for bags, missing resources and reference cycles.
    pub fn resolve(&self, id: u32) -> Option<Value> {
        let mut id = id;
        for _ in 0..MAX_REFERENCE_DEPTH {
            let values = self.values(id);
            let EntryValue::Simple(value) = &preferred(&values)?.value else {
                return None;
            };
            match value {
                Value::Reference(next) => id = *next,
                other => return Some(other.clone()),
            }
        }
        None
    }

    /// A string value: the literal itself, or the resolved reference.
    pub fn string(&self, value: &Value) -> Option<String> {
        match value {
            Value::String(Some(text)) => Some(text.clone()),
            Value::Reference(id) => self.resolve(*id)?.as_str().map(str::to_owned),
            _ => None,
        }
    }

    /// File paths a resource points to (`res/xml/network_security_config.xml`), per
    /// configuration.
    pub fn files(&self, id: u32) -> Vec<(Config, String)> {
        self.values(id)
            .into_iter()
            .filter_map(|resource| match resource.value {
                EntryValue::Simple(Value::String(Some(path))) if path.starts_with("res/") => {
                    Some((resource.config, path))
                }
                _ => None,
            })
            .collect()
    }
}

impl ArscTable {
    /// Package names, in table order.
    fn package_names(&self) -> Vec<String> {
        self.packages
            .iter()
            .map(|package| package.name.clone())
            .collect()
    }

    /// `package:type/entry` for a resource ID.
    fn name(&self, id: u32) -> Option<ResourceName> {
        let (package, type_id, entry_index) = self.locate(id)?;
        let type_name = self.type_name(package, type_id)?;
        let entry = package
            .types
            .iter()
            .filter(|chunk| chunk.type_id == type_id)
            .find_map(|chunk| self.entry_key(package, chunk, entry_index))?;
        Some(ResourceName {
            package: package.name.clone(),
            type_name,
            entry,
        })
    }

    /// Every configuration of a resource.
    fn values(&self, id: u32) -> Vec<ResourceValue> {
        let Some((package, type_id, entry_index)) = self.locate(id) else {
            return Vec::new();
        };
        package
            .types
            .iter()
            .filter(|chunk| chunk.type_id == type_id)
            .filter_map(|chunk| {
                let value = self.entry_value(chunk, entry_index)?;
                Some(ResourceValue {
                    config: chunk.config.clone(),
                    value,
                })
            })
            .collect()
    }

    /// Resource ID of `type/entry` in the first package that has it.
    fn find(&self, type_name: &str, entry_name: &str) -> Option<u32> {
        self.packages.iter().find_map(|package| {
            package
                .types
                .iter()
                .filter(|chunk| {
                    self.type_name(package, chunk.type_id).as_deref() == Some(type_name)
                })
                .find_map(|chunk| {
                    (0..chunk.entry_count).find_map(|entry_index| {
                        let key = self.entry_key(package, chunk, entry_index)?;
                        (key == entry_name).then(|| {
                            (package.id << 24)
                                | (u32::from(chunk.type_id) << 16)
                                | entry_index as u32
                        })
                    })
                })
        })
    }

    fn ids_of_type(&self, type_name: &str) -> Vec<u32> {
        let mut ids = BTreeSet::new();
        for package in &self.packages {
            for chunk in &package.types {
                if self.type_name(package, chunk.type_id).as_deref() != Some(type_name) {
                    continue;
                }
                for entry_index in self.entry_indexes(chunk) {
                    ids.insert(
                        (package.id << 24) | (u32::from(chunk.type_id) << 16) | entry_index as u32,
                    );
                }
            }
        }
        ids.into_iter().collect()
    }

    /// Entry indexes a type chunk holds a value for: the `(index, offset)` pairs of a sparse
    /// chunk, every index with an offset otherwise.
    fn entry_indexes(&self, chunk: &TypeChunk) -> Vec<usize> {
        if chunk.flags & TYPE_FLAG_SPARSE != 0 {
            return (0..chunk.entry_count)
                .filter_map(|pair| u16_at(&self.bytes, chunk.offsets_start + pair * 4))
                .map(usize::from)
                .collect();
        }
        (0..chunk.entry_count)
            .filter(|&entry_index| self.entry_position(chunk, entry_index).is_some())
            .collect()
    }

    /// Locales the app's strings are translated into, sorted (`de`, `en-GB`, `ja`).
    fn locales(&self) -> Vec<String> {
        let mut locales = BTreeSet::new();
        for package in &self.packages {
            for chunk in &package.types {
                if self.type_name(package, chunk.type_id).as_deref() == Some("string")
                    && let Some(locale) = chunk.config.locale()
                {
                    locales.insert(locale);
                }
            }
        }
        locales.into_iter().collect()
    }

    /// Package, type ID and entry index for a resource ID. Package ID 0 (a shared library's
    /// own resources) maps to the first package.
    fn locate(&self, id: u32) -> Option<(&Package, u8, usize)> {
        let package_id = id >> 24;
        let type_id = ((id >> 16) & 0xff) as u8;
        let package = if package_id == 0 {
            self.packages.first()?
        } else {
            self.packages
                .iter()
                .find(|package| package.id == package_id)?
        };
        Some((package, type_id, (id & 0xffff) as usize))
    }

    fn type_name(&self, package: &Package, type_id: u8) -> Option<String> {
        let index = u32::from(type_id).checked_sub(1 + package.type_id_offset)?;
        package.type_names.get(&self.bytes, index)
    }

    /// Absolute position of an entry, or `None` when the chunk has no such entry.
    fn entry_position(&self, chunk: &TypeChunk, entry_index: usize) -> Option<usize> {
        let offset = if chunk.flags & TYPE_FLAG_SPARSE != 0 {
            self.sparse_entry_offset(chunk, entry_index)?
        } else if entry_index >= chunk.entry_count {
            return None;
        } else if chunk.flags & TYPE_FLAG_OFFSET16 != 0 {
            let offset = u16_at(&self.bytes, chunk.offsets_start + entry_index * 2)?;
            if offset == NO_ENTRY_16 {
                return None;
            }
            usize::from(offset) * 4
        } else {
            let offset = u32_at(&self.bytes, chunk.offsets_start + entry_index * 4)?;
            if offset == NO_ENTRY_32 {
                return None;
            }
            offset as usize
        };
        let position = chunk.entries_start.checked_add(offset)?;
        (position < chunk.end).then_some(position)
    }

    /// Sparse chunks list `(entry index, offset / 4)` pairs sorted by index.
    fn sparse_entry_offset(&self, chunk: &TypeChunk, entry_index: usize) -> Option<usize> {
        let (mut low, mut high) = (0, chunk.entry_count);
        while low < high {
            let middle = low + (high - low) / 2;
            let pair = chunk.offsets_start + middle * 4;
            let index = usize::from(u16_at(&self.bytes, pair)?);
            match index.cmp(&entry_index) {
                std::cmp::Ordering::Equal => {
                    return Some(usize::from(u16_at(&self.bytes, pair + 2)?) * 4);
                }
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
            }
        }
        None
    }

    fn entry_key(
        &self,
        package: &Package,
        chunk: &TypeChunk,
        entry_index: usize,
    ) -> Option<String> {
        let position = self.entry_position(chunk, entry_index)?;
        let entry = &self.bytes[..chunk.end];
        let flags = u16_at(entry, position + 2)?;
        let key = if flags & ENTRY_FLAG_COMPACT != 0 {
            u32::from(u16_at(entry, position)?)
        } else {
            u32_at(entry, position + 4)?
        };
        package.key_names.get(&self.bytes, key)
    }

    fn entry_value(&self, chunk: &TypeChunk, entry_index: usize) -> Option<EntryValue> {
        let position = self.entry_position(chunk, entry_index)?;
        let entry = &self.bytes[..chunk.end];
        let size = usize::from(u16_at(entry, position)?);
        let flags = u16_at(entry, position + 2)?;
        if flags & ENTRY_FLAG_COMPACT != 0 {
            // Compact entries hold the data type in the flags' high byte and the data inline.
            let data = u32_at(entry, position + 4)?;
            return Some(EntryValue::Simple(self.value((flags >> 8) as u8, data)));
        }
        if flags & ENTRY_FLAG_COMPLEX != 0 {
            return self.complex_value(entry, position, size);
        }
        let value_at = position.checked_add(size)?;
        let data_type = *entry.get(value_at + 3)?;
        let data = u32_at(entry, value_at + 4)?;
        Some(EntryValue::Simple(self.value(data_type, data)))
    }

    fn complex_value(&self, entry: &[u8], position: usize, size: usize) -> Option<EntryValue> {
        let parent = u32_at(entry, position + 8)?;
        let declared = u32_at(entry, position + 12)? as usize;
        let items_start = position.checked_add(size)?;
        let available = entry.len().saturating_sub(items_start) / MAP_ITEM_LENGTH;
        let items = (0..declared.min(available))
            .filter_map(|item| {
                let at = items_start + item * MAP_ITEM_LENGTH;
                let name = u32_at(entry, at)?;
                let data_type = *entry.get(at + 7)?;
                let data = u32_at(entry, at + 8)?;
                Some((name, self.value(data_type, data)))
            })
            .collect();
        Some(EntryValue::Complex { parent, items })
    }

    fn value(&self, data_type: u8, data: u32) -> Value {
        Value::decode(data_type, data, |index| {
            self.strings.as_ref()?.get(&self.bytes, index)
        })
    }
}

/// Default configuration first, then English without region, then any English, then the first.
fn preferred(values: &[ResourceValue]) -> Option<&ResourceValue> {
    values
        .iter()
        .find(|value| value.config.is_default())
        .or_else(|| {
            values.iter().find(|value| {
                value.config.language().as_deref() == Some("en") && value.config.region().is_none()
            })
        })
        .or_else(|| {
            values
                .iter()
                .find(|value| value.config.language().as_deref() == Some("en"))
        })
        .or_else(|| values.first())
}

/// Indexing state: borrows the table bytes while packages are found.
struct TableIndex<'data> {
    bytes: &'data [u8],
    anomalies: Vec<ResourceAnomaly>,
    strings: Option<StringPool>,
    packages: Vec<Package>,
}

impl TableIndex<'_> {
    fn read_table_chunks(&mut self, header_size: usize, end: usize) -> Result<(), ResourceError> {
        let mut position = header_size;
        while position + CHUNK_HEADER_LENGTH <= end {
            let chunk = match Chunk::read(self.bytes, position, end, CHUNK_HEADER_LENGTH) {
                Ok(chunk) => chunk,
                Err(problem) => {
                    self.anomaly(ResourceAnomalyKind::MalformedChunk(problem), position);
                    break;
                }
            };
            self.check_alignment(&chunk);
            match chunk.kind {
                RES_STRING_POOL_TYPE if self.strings.is_none() => {
                    self.strings =
                        Some(StringPool::parse(&chunk).map_err(ResourceError::StringPool)?);
                }
                RES_TABLE_PACKAGE_TYPE => {
                    match read_package(self.bytes, &chunk, &mut self.anomalies) {
                        Some(package) => self.packages.push(package),
                        None => self.anomaly(ResourceAnomalyKind::MalformedPackage, position),
                    }
                }
                kind => self.anomaly(ResourceAnomalyKind::UnknownChunk { kind }, position),
            }
            position = chunk.end();
        }
        Ok(())
    }

    fn check_alignment(&mut self, chunk: &Chunk<'_>) {
        if !chunk.is_aligned() {
            self.anomaly(ResourceAnomalyKind::Misaligned, chunk.offset);
        }
    }

    fn anomaly(&mut self, kind: ResourceAnomalyKind, offset: usize) {
        self.anomalies.push(ResourceAnomaly { kind, offset });
    }
}

fn read_package(
    bytes: &[u8],
    chunk: &Chunk<'_>,
    anomalies: &mut Vec<ResourceAnomaly>,
) -> Option<Package> {
    if chunk.header_size < PACKAGE_MIN_HEADER_LENGTH {
        return None;
    }
    let id = chunk.u32_at(8)?;
    let name_units: Vec<u16> = (0..PACKAGE_NAME_UNITS)
        .map_while(|unit| {
            chunk
                .u16_at(PACKAGE_NAME_OFFSET + unit * 2)
                .filter(|&code| code != 0)
        })
        .collect();
    let type_names = package_string_pool(bytes, chunk, chunk.u32_at(268)? as usize)?;
    let key_names = package_string_pool(bytes, chunk, chunk.u32_at(276)? as usize)?;
    let type_id_offset = if chunk.header_size >= 288 {
        chunk.u32_at(284)?
    } else {
        0
    };
    let mut package = Package {
        id,
        name: String::from_utf16_lossy(&name_units),
        type_names,
        key_names,
        type_id_offset,
        types: Vec::new(),
    };
    read_package_chunks(bytes, chunk, &mut package, anomalies);
    Some(package)
}

/// The type and key string pools sit at offsets from the package start.
fn package_string_pool(bytes: &[u8], package: &Chunk<'_>, relative: usize) -> Option<StringPool> {
    let pool = Chunk::read(
        bytes,
        package.offset.checked_add(relative)?,
        package.end(),
        CHUNK_HEADER_LENGTH,
    )
    .ok()?;
    (pool.kind == RES_STRING_POOL_TYPE)
        .then(|| StringPool::parse(&pool).ok())
        .flatten()
}

fn read_package_chunks(
    bytes: &[u8],
    package_chunk: &Chunk<'_>,
    package: &mut Package,
    anomalies: &mut Vec<ResourceAnomaly>,
) {
    let mut position = package_chunk.offset + package_chunk.header_size;
    let end = package_chunk.end();
    while position + CHUNK_HEADER_LENGTH <= end {
        let chunk = match Chunk::read(bytes, position, end, CHUNK_HEADER_LENGTH) {
            Ok(chunk) => chunk,
            Err(problem) => {
                anomalies.push(ResourceAnomaly {
                    kind: ResourceAnomalyKind::MalformedChunk(problem),
                    offset: position,
                });
                return;
            }
        };
        if !chunk.is_aligned() {
            anomalies.push(ResourceAnomaly {
                kind: ResourceAnomalyKind::Misaligned,
                offset: position,
            });
        }
        match chunk.kind {
            RES_TABLE_TYPE_TYPE => match read_type_chunk(&chunk) {
                Some(type_chunk) => package.types.push(type_chunk),
                None => anomalies.push(ResourceAnomaly {
                    kind: ResourceAnomalyKind::MalformedTypeChunk,
                    offset: position,
                }),
            },
            RES_STRING_POOL_TYPE
            | RES_TABLE_TYPE_SPEC_TYPE
            | RES_TABLE_LIBRARY_TYPE
            | RES_TABLE_OVERLAYABLE_TYPE
            | RES_TABLE_OVERLAYABLE_POLICY_TYPE
            | RES_TABLE_STAGED_ALIAS_TYPE => {}
            kind => anomalies.push(ResourceAnomaly {
                kind: ResourceAnomalyKind::UnknownChunk { kind },
                offset: position,
            }),
        }
        position = chunk.end();
    }
}

fn read_type_chunk(chunk: &Chunk<'_>) -> Option<TypeChunk> {
    if chunk.header_size < TYPE_HEADER_FIXED_LENGTH + 4 {
        return None;
    }
    let type_id = *chunk.bytes.get(8)?;
    let flags = *chunk.bytes.get(9)?;
    let entry_count = chunk.u32_at(12)? as usize;
    let entries_start = chunk.u32_at(16)? as usize;
    let config_size = (chunk.u32_at(TYPE_HEADER_FIXED_LENGTH)? as usize)
        .min(chunk.header_size - TYPE_HEADER_FIXED_LENGTH);
    let config = Config::from_bytes(
        &chunk.bytes[TYPE_HEADER_FIXED_LENGTH..TYPE_HEADER_FIXED_LENGTH + config_size],
    );

    let offset_width = if flags & TYPE_FLAG_OFFSET16 != 0 && flags & TYPE_FLAG_SPARSE == 0 {
        2
    } else {
        4
    };
    let offsets_end = entry_count
        .checked_mul(offset_width)?
        .checked_add(chunk.header_size)?;
    if type_id == 0 || offsets_end > entries_start || entries_start > chunk.bytes.len() {
        return None;
    }
    Some(TypeChunk {
        type_id,
        flags,
        entry_count,
        offsets_start: chunk.offset + chunk.header_size,
        entries_start: chunk.offset + entries_start,
        end: chunk.end(),
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_two_and_three_letter_codes() {
        assert_eq!(
            unpack_language_or_region(*b"en", b'a').as_deref(),
            Some("en")
        );
        assert_eq!(unpack_language_or_region([0, 0], b'a'), None);
        // "fil" packed: f=5, i=8, l=11 -> 1 01011 01000 00101 (big-endian bits) = 0xAD05.
        assert_eq!(
            unpack_language_or_region([0xad, 0x05], b'a').as_deref(),
            Some("fil")
        );
    }

    #[test]
    fn config_qualifiers_read_like_aapt2() {
        let mut raw = vec![0u8; 64];
        raw[0] = 64;
        assert!(Config::from_bytes(&raw).is_default());
        assert_eq!(Config::from_bytes(&raw).qualifiers(), "default");
        raw[8..10].copy_from_slice(b"en");
        raw[10..12].copy_from_slice(b"GB");
        raw[14..16].copy_from_slice(&480u16.to_le_bytes());
        raw[24..26].copy_from_slice(&26u16.to_le_bytes());
        let config = Config::from_bytes(&raw);
        assert_eq!(config.qualifiers(), "en-rGB-xxhdpi-v26");
        assert_eq!(config.locale().as_deref(), Some("en-GB"));
    }

    #[test]
    fn rejects_files_that_are_not_tables() {
        assert_eq!(
            ResourceTable::parse(vec![3, 0, 8, 0, 8, 0, 0, 0]).unwrap_err(),
            ResourceError::NotResourceTable
        );
        assert_eq!(
            ResourceTable::parse(Vec::new()).unwrap_err(),
            ResourceError::NotResourceTable
        );
    }
}
