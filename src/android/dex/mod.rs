//! DEX files: an Android app's compiled code, read with bounds checks from untrusted bytes.
//!
//! This first stage reads what an inventory needs, and checks what ART checks before it loads
//! a file: the header, the map list, the string and type tables, and the class definitions with
//! their superclass and interfaces, plus the Adler-32 checksum and SHA-1 signature. Proto, field
//! and method tables are bounds-checked and counted, not read.
//!
//! Deferred to Phase 1B: method and field references, code items, and the `invoke-*` call sites
//! that code rules need.
//!
//! Every offset and count is checked against the file before it is used. ID tables and the map
//! list must lie in their own logical file, so the memory a file can claim grows with its size.
//! Strings and interface lists may be shared, so two budgets bound the work of reading them.
//! Reaching a budget is reported, never silent ([`DexFile::complete`]).
//!
//! Which problems ART refuses is taken from its loader and verifier (`libdexfile`) and checked
//! against AOSP's `dexdump` in the tests (`tests/fixtures/android/dex/art-verdicts.txt`).

mod header;
mod package;
mod strings;

use std::collections::HashMap;
use std::collections::HashSet;
use std::mem::discriminant;

use sha1::{Digest, Sha1};

use crate::android::chunk::{u16_at, u32_at};
use header::CONTAINER_VERSION;
pub use header::{Header, Table};
pub use package::{CodeSummary, DexEntry, PackageCount, ShadowedClass, read_dex_files, summarise};
use strings::StringTable;

/// Largest DEX file read. Real ones stay far below it (the 64K method-reference limit keeps
/// each under a few tens of megabytes); this only stops absurd inputs.
pub const MAX_DEX_BYTES: usize = 256 * 1024 * 1024;
/// Logical files read from one version 041 container.
const MAX_CONTAINER_FILES: usize = 1024;
/// `NO_INDEX`: an absent index.
const NO_INDEX: u32 = u32::MAX;
/// `TYPE_HEADER_ITEM` in the map list.
const TYPE_HEADER_ITEM: u16 = 0x0000;
/// `TYPE_MAP_LIST` in the map list.
const TYPE_MAP_LIST: u16 = 0x1000;
/// Map item types ART knows (`DexFile::MapItemType`).
const KNOWN_MAP_TYPES: [u16; 21] = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x1000, 0x1001, 0x1002,
    0x1003, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0xF000,
];

/// Why a DEX file, or a section of a container, could not be read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexError {
    /// The archive entry could not be read (the reason from the archive reader).
    Unreadable(String),
    /// Larger than [`MAX_DEX_BYTES`].
    TooLarge {
        /// Its size.
        length: u64,
    },
    /// The package's DEX files together exceed what msec reads from one package; this one was
    /// not read.
    PackageBudgetExhausted,
    /// No `dex\n` magic.
    NotDex,
    /// Compact DEX (`cdex`): ART's on-device format, found in VDEX files rather than APKs. Not
    /// analysed.
    CompactDex,
    /// A version ART does not load (it knows 035 and 037 to 041), escaped.
    UnsupportedVersion(String),
    /// The file is shorter than its header, or than the size its header declares. ART rejects
    /// it.
    Truncated {
        /// Bytes present.
        length: u64,
        /// Bytes needed.
        needed: u64,
    },
    /// A byte-swapped file (`REVERSE_ENDIAN_CONSTANT`). ART rejects it.
    ByteSwapped,
    /// An endian tag that is neither constant. ART rejects it.
    BadEndianTag(u32),
    /// A header size other than the version's. ART rejects it.
    BadHeaderSize {
        /// As declared.
        declared: u32,
        /// For this version.
        expected: u32,
    },
    /// A declared file size smaller than the header. ART rejects it.
    BadFileSize(u32),
    /// A version 041 container whose sections do not fit together. ART rejects it.
    BadContainer(&'static str),
    /// A version 041 container with more logical files than msec reads (1,024); the ones after
    /// were not read.
    TooManyLogicalFiles,
    /// A table the inventory needs (string IDs, type IDs, class definitions) lies outside the
    /// file. ART rejects it.
    TableOutOfBounds(&'static str),
}

impl std::fmt::Display for DexError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(reason) => write!(formatter, "cannot read the entry: {reason}"),
            Self::TooLarge { length } => write!(
                formatter,
                "{length} bytes, more than the {MAX_DEX_BYTES} msec reads"
            ),
            Self::PackageBudgetExhausted => formatter.write_str(
                "not read: the package's DEX files exceed what msec reads from one package",
            ),
            Self::NotDex => formatter.write_str("not a DEX file"),
            Self::CompactDex => formatter.write_str("compact DEX (cdex), which is not analysed"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "DEX version {version} is not one ART loads")
            }
            Self::Truncated { length, needed } => {
                write!(formatter, "truncated: {length} bytes, {needed} needed")
            }
            Self::ByteSwapped => formatter.write_str("byte-swapped DEX file, which ART rejects"),
            Self::BadEndianTag(tag) => write!(formatter, "unexpected endian tag {tag:#010x}"),
            Self::BadHeaderSize { declared, expected } => write!(
                formatter,
                "header size {declared:#x}, expected {expected:#x}"
            ),
            Self::BadFileSize(size) => {
                write!(formatter, "file size {size} is smaller than the header")
            }
            Self::BadContainer(problem) => write!(formatter, "invalid DEX container: {problem}"),
            Self::TooManyLogicalFiles => write!(
                formatter,
                "more than {MAX_CONTAINER_FILES} logical files; the rest were not read"
            ),
            Self::TableOutOfBounds(table) => {
                write!(formatter, "the {table} table is outside the file")
            }
        }
    }
}

impl DexError {
    /// True when ART refuses the file; false for msec's own limits and for entries the archive
    /// reader could not read. The tests check each rejection against `dexdump`.
    pub fn rejected_by_android(&self) -> bool {
        !matches!(
            self,
            Self::Unreadable(_)
                | Self::TooLarge { .. }
                | Self::PackageBudgetExhausted
                | Self::TooManyLogicalFiles
        )
    }
}

impl std::error::Error for DexError {}

/// Something unusual in a DEX file that did not stop it being read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexAnomaly {
    /// The first occurrence.
    pub kind: DexAnomalyKind,
    /// Further occurrences of the same kind, not listed separately (a hostile file can have
    /// millions).
    pub repeats: u32,
}

/// What kind of oddity was found.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DexAnomalyKind {
    /// The Adler-32 checksum does not match. ART's verifier refuses the file when it checks
    /// checksums, as `dexdump` does; not every way of opening a file checks them, so it is not
    /// counted as a rejection.
    ChecksumMismatch {
        /// In the header.
        declared: u32,
        /// Of the bytes.
        computed: u32,
    },
    /// The SHA-1 signature does not match. ART never checks it; a mismatch means the file was
    /// edited after it was built, by a tool that fixed only the checksum.
    SignatureMismatch,
    /// Bytes after the declared end of the file (or container). ART ignores them.
    TrailingData {
        /// How many.
        bytes: u64,
    },
    /// The map list is unreadable or invalid. ART rejects the file.
    InvalidMap(MapProblem),
    /// A proto, field or method ID table lies outside the file. ART rejects the file.
    TableOutOfBounds(&'static str),
    /// A string ART rejects: out of bounds, wrong length, or bytes MUTF-8 does not allow.
    InvalidString {
        /// String ID.
        index: u32,
    },
    /// String IDs not sorted by UTF-16 code units, or repeated. ART rejects the file.
    StringsOutOfOrder {
        /// The first ID out of order.
        index: u32,
    },
    /// A type ID whose descriptor index is outside the string table. ART rejects the file.
    BadDescriptorIndex {
        /// Type ID.
        type_index: u32,
    },
    /// A class definition whose class type is outside the type table. ART rejects the file.
    BadClassIndex {
        /// Position in the class definition table.
        class_def: u32,
    },
    /// A superclass outside the type table. ART rejects the file.
    BadSuperclassIndex {
        /// Position in the class definition table.
        class_def: u32,
    },
    /// An interface list outside the file, or naming a type outside the type table. ART
    /// rejects the file.
    BadInterfaces {
        /// Position in the class definition table.
        class_def: u32,
    },
    /// Two class definitions for one type. ART rejects the file.
    DuplicateClass {
        /// The type ID defined twice.
        type_index: u32,
    },
    /// String IDs share bytes, so decoding them all would cost more than the file's size: this
    /// string and the ones after it were not read. Not an Android limit.
    StringBudgetExhausted {
        /// First string ID not read.
        first_unread: u32,
    },
    /// Interface lists overlap so that reading them all would cost more than the file's size:
    /// this class definition's list was not read, nor any list first used after it. Not an
    /// Android limit.
    InterfaceBudgetExhausted {
        /// Position in the class definition table.
        class_def: u32,
    },
}

/// How the map list is invalid. ART's `CheckMap` rejects each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapProblem {
    /// `map_off` or the list itself lies outside the file.
    OutOfBounds,
    /// Items not in increasing offset order.
    OutOfOrder,
    /// A section type listed twice.
    DuplicateType(u16),
    /// A section type ART does not know.
    UnknownType(u16),
    /// An item past the end of the file.
    ItemOutOfBounds(u16),
    /// No header entry.
    MissingHeader,
    /// No entry for the map list itself.
    MissingMapList,
}

impl DexAnomalyKind {
    /// True when ART refuses the file. The tests check each such claim against `dexdump`.
    pub fn rejected_by_android(&self) -> bool {
        !matches!(
            self,
            Self::ChecksumMismatch { .. }
                | Self::SignatureMismatch
                | Self::TrailingData { .. }
                | Self::StringBudgetExhausted { .. }
                | Self::InterfaceBudgetExhausted { .. }
        )
    }

    /// True when msec stopped reading part of the file (the inventory is incomplete).
    pub fn limits_inventory(&self) -> bool {
        matches!(
            self,
            Self::StringBudgetExhausted { .. } | Self::InterfaceBudgetExhausted { .. }
        )
    }
}

/// Anomalies of a file, one entry per kind.
#[derive(Debug, Default)]
struct Anomalies(Vec<DexAnomaly>);

impl Anomalies {
    fn record(&mut self, kind: DexAnomalyKind) {
        match self
            .0
            .iter_mut()
            .find(|anomaly| discriminant(&anomaly.kind) == discriminant(&kind))
        {
            Some(anomaly) => anomaly.repeats = anomaly.repeats.saturating_add(1),
            None => self.0.push(DexAnomaly { kind, repeats: 0 }),
        }
    }
}

/// Work allowed for reading the shared parts of a `.dex` file, across all its logical files.
///
/// In a valid file each string and interface list has its own bytes, so reading them all costs
/// less than the file's size; a hostile file can point many IDs (or many sections of a
/// container) at the same long string or list and cost that many times more. A version 041
/// container may legitimately share data between its logical files, so the budgets allow twice
/// the file's size. Past a budget, the rest is left unread and reported
/// ([`DexAnomalyKind::StringBudgetExhausted`], [`DexAnomalyKind::InterfaceBudgetExhausted`]).
struct Budgets {
    /// String bytes still to decode.
    string_bytes: usize,
    /// Interface list entries (two bytes each) still to read.
    interface_entries: usize,
}

impl Budgets {
    fn for_length(length: usize) -> Self {
        Self {
            string_bytes: length.saturating_mul(2),
            interface_entries: length,
        }
    }
}

/// One entry of the map list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItem {
    /// `TYPE_*` constant.
    pub item_type: u16,
    /// Number of items.
    pub count: u32,
    /// File offset.
    pub offset: u32,
}

/// One class definition. Indexes refer to the file's tables; [`DexFile`] resolves them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDef {
    /// Type ID of the class.
    pub class_type: u32,
    /// `ACC_*` flags.
    pub access_flags: u32,
    /// Type ID of the superclass; `None` for `java.lang.Object` (or an invalid index).
    pub superclass_type: Option<u32>,
    /// Range in the file's interface entries.
    interfaces: (u32, u32),
    /// String ID of the source file name, when recorded.
    pub source_file: Option<u32>,
    /// `class_data_off`: 0 when the class has no fields or methods.
    pub class_data_offset: u32,
}

/// One logical DEX file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexFile {
    /// The header.
    pub header: Header,
    /// The Adler-32 checksum matches.
    pub checksum_valid: bool,
    /// The SHA-1 signature matches.
    pub signature_valid: bool,
    /// The map list, as stored (empty when unreadable).
    pub map: Vec<MapItem>,
    /// Class definitions in table order, without those whose class type is invalid.
    pub classes: Vec<ClassDef>,
    /// What was unusual, in the order found.
    pub anomalies: Vec<DexAnomaly>,
    strings: StringTable,
    /// Descriptor string ID of each type ID ([`NO_INDEX`] when invalid).
    types: Vec<u32>,
    /// Interface type IDs of all classes, back to back; lists shared by several classes (d8
    /// shares identical lists) are stored once.
    interface_types: Vec<u16>,
}

/// A `.dex` file: one logical DEX file, or several in a version 041 container.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DexContainer {
    /// The logical files read, in order.
    pub files: Vec<DexFile>,
    /// Why reading stopped: before the first file (nothing was read), or at a later section of
    /// a container (the files before it were read).
    pub error: Option<DexError>,
}

impl DexContainer {
    /// Everything in the file was read: no error and no budget reached.
    pub fn complete(&self) -> bool {
        self.error.is_none() && self.files.iter().all(DexFile::complete)
    }
}

/// Reads a `.dex` file, every logical file of a version 041 container included.
pub fn parse(bytes: &[u8]) -> DexContainer {
    let mut container = DexContainer::default();
    if bytes.len() > MAX_DEX_BYTES {
        container.error = Some(DexError::TooLarge {
            length: bytes.len() as u64,
        });
        return container;
    }
    let mut budgets = Budgets::for_length(bytes.len());
    let mut at = 0;
    loop {
        match DexFile::parse_at(bytes, at, &mut budgets) {
            Ok(file) => {
                let next = at + file.header.file_size as usize;
                let more = file.header.version >= CONTAINER_VERSION
                    && next < file.header.container_size as usize;
                container.files.push(file);
                if !more {
                    return container;
                }
                if container.files.len() == MAX_CONTAINER_FILES {
                    container.error = Some(DexError::TooManyLogicalFiles);
                    return container;
                }
                at = next;
            }
            Err(error) => {
                container.error = Some(error);
                return container;
            }
        }
    }
}

impl DexFile {
    /// Reads the logical file whose header is at `at` in the physical file `bytes`.
    fn parse_at(bytes: &[u8], at: usize, budgets: &mut Budgets) -> Result<Self, DexError> {
        let header = Header::parse(bytes, at)?;
        let mut anomalies = Anomalies::default();
        // Data (strings, interface lists) may be anywhere from this header to the end of the
        // container; ID tables and the map list follow their own header, inside the logical
        // file. Logical files do not overlap, so neither do their tables.
        let (lower, upper) = extent(&header, bytes.len(), at, &mut anomalies)?;
        let end = at + header.file_size as usize;
        let own = (at, end);
        let computed = adler2::adler32_slice(&bytes[at + 12..end]);
        let checksum_valid = computed == header.checksum;
        if !checksum_valid {
            anomalies.record(DexAnomalyKind::ChecksumMismatch {
                declared: header.checksum,
                computed,
            });
        }
        let signature_valid = Sha1::digest(&bytes[at + 32..end]).as_slice() == header.signature;
        if !signature_valid {
            anomalies.record(DexAnomalyKind::SignatureMismatch);
        }

        let in_file = |table: Table, item_size: u64| -> bool {
            table.count == 0
                || (table.offset as usize >= own.0
                    && u64::from(table.offset) + u64::from(table.count) * item_size <= own.1 as u64)
        };
        for (name, table, item_size) in [
            ("string_ids", header.string_ids, 4),
            ("type_ids", header.type_ids, 4),
            ("class_defs", header.class_defs, 32),
        ] {
            if !in_file(table, item_size) {
                return Err(DexError::TableOutOfBounds(name));
            }
        }
        for (name, table, item_size) in [
            ("proto_ids", header.proto_ids, 12),
            ("field_ids", header.field_ids, 8),
            ("method_ids", header.method_ids, 8),
        ] {
            if !in_file(table, item_size) {
                anomalies.record(DexAnomalyKind::TableOutOfBounds(name));
            }
        }

        let map = read_map(bytes, &header, own, upper, &mut anomalies);
        let strings = StringTable::read(
            bytes,
            header.string_ids.offset as usize,
            header.string_ids.count,
            (lower, upper),
            &mut budgets.string_bytes,
            &mut anomalies,
        );
        let types = read_types(bytes, &header, strings.len(), &mut anomalies);
        let mut file = Self {
            header,
            checksum_valid,
            signature_valid,
            map,
            classes: Vec::new(),
            anomalies: Vec::new(),
            strings,
            types,
            interface_types: Vec::new(),
        };
        file.read_classes(
            bytes,
            (lower, upper),
            &mut budgets.interface_entries,
            &mut anomalies,
        );
        file.anomalies = anomalies.0;
        Ok(file)
    }

    /// Reads the class definitions, their interface lists, and checks for redefinitions.
    fn read_classes(
        &mut self,
        bytes: &[u8],
        bounds: (usize, usize),
        interface_budget: &mut usize,
        anomalies: &mut Anomalies,
    ) {
        let table = self.header.class_defs;
        let type_count = self.types.len() as u32;
        let mut defined: HashSet<u32> = HashSet::new();
        let mut lists = InterfaceLists {
            by_offset: HashMap::new(),
            budget: interface_budget,
        };
        for position in 0..table.count {
            let at = table.offset as usize + 32 * position as usize;
            let field = |index: usize| {
                u32_at(bytes, at + 4 * index).expect("the class_defs table was bounds-checked")
            };
            let class_type = field(0);
            if class_type >= type_count {
                anomalies.record(DexAnomalyKind::BadClassIndex {
                    class_def: position,
                });
                continue;
            }
            if !defined.insert(class_type) {
                anomalies.record(DexAnomalyKind::DuplicateClass {
                    type_index: class_type,
                });
            }
            let superclass = field(2);
            if superclass != NO_INDEX && superclass >= type_count {
                anomalies.record(DexAnomalyKind::BadSuperclassIndex {
                    class_def: position,
                });
            }
            let interfaces = match lists.read(
                bytes,
                field(3),
                bounds,
                type_count,
                &mut self.interface_types,
            ) {
                Ok(range) => range,
                Err(InterfaceProblem::Invalid) => {
                    anomalies.record(DexAnomalyKind::BadInterfaces {
                        class_def: position,
                    });
                    (0, 0)
                }
                Err(InterfaceProblem::BudgetExhausted) => {
                    anomalies.record(DexAnomalyKind::InterfaceBudgetExhausted {
                        class_def: position,
                    });
                    (0, 0)
                }
            };
            let source_file = field(4);
            self.classes.push(ClassDef {
                class_type,
                access_flags: field(1),
                superclass_type: (superclass < type_count).then_some(superclass),
                interfaces,
                source_file: (source_file != NO_INDEX).then_some(source_file),
                class_data_offset: field(6),
            });
        }
    }

    /// Format version (35 to 41).
    pub fn version(&self) -> u16 {
        self.header.version
    }

    /// Everything in the file was read: no budget reached.
    pub fn complete(&self) -> bool {
        !self
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind.limits_inventory())
    }

    /// Number of string IDs.
    pub fn string_count(&self) -> usize {
        self.strings.len()
    }

    /// The string with this ID, as UTF-8 (unpaired surrogates become U+FFFD); `None` when out
    /// of range or not read.
    pub fn string(&self, index: u32) -> Option<&str> {
        self.strings.get(index)
    }

    /// All strings in ID order; `None` for one that was not read.
    pub fn strings(&self) -> impl Iterator<Item = Option<&str>> {
        self.strings.iter()
    }

    /// Number of type IDs.
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// The descriptor of a type (`Lcom/example/Main;`, `[I`).
    pub fn type_descriptor(&self, type_index: u32) -> Option<&str> {
        let descriptor = *self.types.get(type_index as usize)?;
        self.strings.get(descriptor)
    }

    /// The class's descriptor.
    pub fn class_descriptor(&self, class: &ClassDef) -> Option<&str> {
        self.type_descriptor(class.class_type)
    }

    /// The superclass's descriptor; `None` for `java.lang.Object`.
    pub fn superclass(&self, class: &ClassDef) -> Option<&str> {
        self.type_descriptor(class.superclass_type?)
    }

    /// The descriptors of the interfaces the class implements, in declaration order.
    pub fn interfaces(&self, class: &ClassDef) -> impl Iterator<Item = Option<&str>> {
        let (start, length) = class.interfaces;
        self.interface_types[start as usize..(start + length) as usize]
            .iter()
            .map(|&type_index| self.type_descriptor(u32::from(type_index)))
    }

    /// The source file name recorded for the class (`Main.java`).
    pub fn source_file(&self, class: &ClassDef) -> Option<&str> {
        self.strings.get(class.source_file?)
    }

    /// Markers D8, R8 and L8 leave in the string table (`~~R8{"backend":"dex",...}`): which
    /// compiler built the code, in which mode, for which minimum API, and whether R8 shrank it.
    pub fn compiler_markers(&self) -> impl Iterator<Item = &str> {
        self.strings().flatten().filter(|text| {
            ["~~D8{", "~~R8{", "~~L8{"]
                .iter()
                .any(|prefix| text.starts_with(prefix))
        })
    }
}

/// Bytes a logical file's offsets may point into, as `(lower, upper)`, after checking the
/// declared sizes against the bytes present. Up to version 040 that is the file itself; in a
/// container, a logical file may use any later byte of the container (but not earlier ones).
fn extent(
    header: &Header,
    length: usize,
    at: usize,
    anomalies: &mut Anomalies,
) -> Result<(usize, usize), DexError> {
    if header.file_size < header.header_size {
        return Err(DexError::BadFileSize(header.file_size));
    }
    let file_size = header.file_size as usize;
    if header.version < CONTAINER_VERSION {
        // Only a container's sections follow the first; theirs are version 041 too. An older
        // header here would be sized against the whole buffer, not what follows it.
        if at != 0 {
            return Err(DexError::BadContainer(
                "a section after the first is older than version 041",
            ));
        }
        if file_size > length {
            return Err(DexError::Truncated {
                length: length as u64,
                needed: file_size as u64,
            });
        }
        if file_size < length {
            anomalies.record(DexAnomalyKind::TrailingData {
                bytes: (length - file_size) as u64,
            });
        }
        return Ok((0, file_size));
    }
    if header.header_offset as usize != at {
        return Err(DexError::BadContainer(
            "a header_offset does not match where the header is",
        ));
    }
    let container_size = header.container_size as usize;
    if container_size > length {
        return Err(DexError::Truncated {
            length: length as u64,
            needed: container_size as u64,
        });
    }
    if file_size > container_size.saturating_sub(at) {
        return Err(DexError::BadContainer(
            "a file_size runs past the container",
        ));
    }
    if at == 0 && container_size < length {
        anomalies.record(DexAnomalyKind::TrailingData {
            bytes: (length - container_size) as u64,
        });
    }
    Ok((at, container_size))
}

/// Reads and checks the map list. Problems are recorded; the items read are returned.
///
/// The list itself must lie in its own logical file (`own`); its items may point anywhere in the
/// bytes the file can use (`data_end`), since a container's data can be shared.
fn read_map(
    bytes: &[u8],
    header: &Header,
    (own_start, own_end): (usize, usize),
    data_end: usize,
    anomalies: &mut Anomalies,
) -> Vec<MapItem> {
    let offset = header.map_offset as usize;
    let count = (offset >= own_start && offset < own_end)
        .then(|| u32_at(&bytes[..own_end], offset))
        .flatten();
    let fits =
        count.is_some_and(|count| (offset as u64) + 4 + 12 * u64::from(count) <= own_end as u64);
    let (Some(count), true) = (count, fits) else {
        anomalies.record(DexAnomalyKind::InvalidMap(MapProblem::OutOfBounds));
        return Vec::new();
    };
    let items: Vec<MapItem> = (0..count as usize)
        .map(|index| {
            let at = offset + 4 + 12 * index;
            MapItem {
                item_type: u16_at(bytes, at).expect("the map was bounds-checked"),
                count: u32_at(bytes, at + 4).expect("the map was bounds-checked"),
                offset: u32_at(bytes, at + 8).expect("the map was bounds-checked"),
            }
        })
        .collect();
    let mut seen: HashSet<u16> = HashSet::new();
    for (index, item) in items.iter().enumerate() {
        if !KNOWN_MAP_TYPES.contains(&item.item_type) {
            anomalies.record(DexAnomalyKind::InvalidMap(MapProblem::UnknownType(
                item.item_type,
            )));
        }
        if !seen.insert(item.item_type) {
            anomalies.record(DexAnomalyKind::InvalidMap(MapProblem::DuplicateType(
                item.item_type,
            )));
        }
        if index > 0 && item.offset <= items[index - 1].offset {
            anomalies.record(DexAnomalyKind::InvalidMap(MapProblem::OutOfOrder));
        }
        if item.offset as usize >= data_end {
            anomalies.record(DexAnomalyKind::InvalidMap(MapProblem::ItemOutOfBounds(
                item.item_type,
            )));
        }
    }
    if !seen.contains(&TYPE_HEADER_ITEM) {
        anomalies.record(DexAnomalyKind::InvalidMap(MapProblem::MissingHeader));
    }
    if !seen.contains(&TYPE_MAP_LIST) {
        anomalies.record(DexAnomalyKind::InvalidMap(MapProblem::MissingMapList));
    }
    items
}

/// Reads the type IDs: each is a descriptor's string ID.
fn read_types(
    bytes: &[u8],
    header: &Header,
    string_count: usize,
    anomalies: &mut Anomalies,
) -> Vec<u32> {
    (0..header.type_ids.count)
        .map(|type_index| {
            let descriptor = u32_at(
                bytes,
                header.type_ids.offset as usize + 4 * type_index as usize,
            )
            .expect("the type_ids table was bounds-checked");
            if descriptor as usize >= string_count {
                anomalies.record(DexAnomalyKind::BadDescriptorIndex { type_index });
                return NO_INDEX;
            }
            descriptor
        })
        .collect()
}

/// Interface lists (`type_list`s) read so far in one logical file, by offset.
struct InterfaceLists<'budget> {
    /// Range in `DexFile::interface_types` of the list at each offset.
    by_offset: HashMap<u32, (u32, u32)>,
    /// Entries still allowed in the container ([`Budgets::interface_entries`]).
    budget: &'budget mut usize,
}

enum InterfaceProblem {
    Invalid,
    BudgetExhausted,
}

impl InterfaceLists<'_> {
    /// The list at `offset` (0: none), read once and shared by every class that uses it.
    fn read(
        &mut self,
        bytes: &[u8],
        offset: u32,
        (lower, upper): (usize, usize),
        type_count: u32,
        entries: &mut Vec<u16>,
    ) -> Result<(u32, u32), InterfaceProblem> {
        if offset == 0 {
            return Ok((0, 0));
        }
        if let Some(&range) = self.by_offset.get(&offset) {
            return Ok(range);
        }
        let at = offset as usize;
        if at < lower || !at.is_multiple_of(4) {
            return Err(InterfaceProblem::Invalid);
        }
        let length = u32_at(&bytes[..upper], at).ok_or(InterfaceProblem::Invalid)? as usize;
        if (at as u64) + 4 + 2 * length as u64 > upper as u64 {
            return Err(InterfaceProblem::Invalid);
        }
        // Charged before the entries are checked, so an invalid list read again and again
        // still uses the budget up.
        if length > *self.budget {
            *self.budget = 0;
            return Err(InterfaceProblem::BudgetExhausted);
        }
        *self.budget -= length;
        let start = entries.len() as u32;
        for index in 0..length {
            let type_index =
                u16_at(bytes, at + 4 + 2 * index).expect("the list was bounds-checked");
            if u32::from(type_index) >= type_count {
                entries.truncate(start as usize);
                return Err(InterfaceProblem::Invalid);
            }
            entries.push(type_index);
        }
        let range = (start, length as u32);
        self.by_offset.insert(offset, range);
        Ok(range)
    }
}
