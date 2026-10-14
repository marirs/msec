//! ELF files (Android native libraries), read with bounds checks from untrusted bytes.
//!
//! Android's dynamic linker works from program headers and the dynamic segment; section headers
//! can be stripped or corrupted (an anti-analysis trick) without affecting loading. So security
//! properties are taken from program headers and dynamic entries; section headers only add the
//! static symbol table, debug sections and the `.comment` (compiler) strings.

/// `PT_LOAD`.
pub const PT_LOAD: u32 = 1;
/// `PT_DYNAMIC`.
pub const PT_DYNAMIC: u32 = 2;
/// `PT_GNU_STACK`: its flags say whether the stack is executable.
pub const PT_GNU_STACK: u32 = 0x6474_e551;
/// `PT_GNU_RELRO`: the region made read-only after relocation.
pub const PT_GNU_RELRO: u32 = 0x6474_e552;
/// Segment flag: executable.
pub const PF_X: u32 = 1;

/// `DT_NEEDED`.
pub const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
/// `DT_RPATH`.
pub const DT_RPATH: i64 = 15;
/// `DT_DEBUG`: present in executables (MobSF uses it to tell PIE from a shared object).
pub const DT_DEBUG: i64 = 21;
/// `DT_TEXTREL`: relocations patch the text segment.
pub const DT_TEXTREL: i64 = 22;
/// `DT_BIND_NOW`.
pub const DT_BIND_NOW: i64 = 24;
/// `DT_RUNPATH`.
pub const DT_RUNPATH: i64 = 29;
/// `DT_FLAGS`.
pub const DT_FLAGS: i64 = 30;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
/// `DT_FLAGS_1`.
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;
/// `DF_TEXTREL` in `DT_FLAGS`.
pub const DF_TEXTREL: u64 = 0x4;
/// `DF_BIND_NOW` in `DT_FLAGS`.
pub const DF_BIND_NOW: u64 = 0x8;
/// `DF_1_NOW` in `DT_FLAGS_1`.
pub const DF_1_NOW: u64 = 0x1;

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const SHT_NOBITS: u32 = 8;

/// Caps that keep a hostile file from costing more than a large real one.
const MAX_DYNAMIC_ENTRIES: usize = 65_536;
const MAX_SYMBOLS: usize = 1_000_000;
const MAX_NAME_LENGTH: usize = 4096;
const MAX_COMMENTS: usize = 16;

/// 32- or 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// ELFCLASS32.
    Elf32,
    /// ELFCLASS64.
    Elf64,
}

/// `e_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfKind {
    /// `ET_REL`: relocatable object.
    Relocatable,
    /// `ET_EXEC`: fixed-address executable.
    Executable,
    /// `ET_DYN`: shared object or position-independent executable.
    Shared,
    /// `ET_CORE`.
    Core,
    /// Anything else.
    Other(u16),
}

/// The architecture (`e_machine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Machine(pub u16);

impl Machine {
    /// `AArch64`, `ARM`, `x86-64`, ...
    pub fn name(self) -> &'static str {
        match self.0 {
            3 => "x86",
            8 => "MIPS",
            40 => "ARM",
            62 => "x86-64",
            183 => "AArch64",
            243 => "RISC-V",
            _ => "other",
        }
    }
}

/// A program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// `p_type`.
    pub kind: u32,
    /// `p_flags`.
    pub flags: u32,
    /// `p_offset`.
    pub offset: u64,
    /// `p_vaddr`.
    pub vaddr: u64,
    /// `p_filesz`.
    pub file_size: u64,
    /// `p_memsz`.
    pub memory_size: u64,
    /// `p_align`.
    pub align: u64,
}

/// A section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Name from the section name table (empty when unreadable).
    pub name: String,
    /// `sh_type`.
    pub kind: u32,
    /// `sh_offset`.
    pub offset: u64,
    /// `sh_size`.
    pub size: u64,
    /// `sh_link`.
    pub link: u32,
    /// `sh_entsize`.
    pub entry_size: u64,
}

/// A symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Name.
    pub name: String,
    /// Defined in this file (not an import).
    pub defined: bool,
    /// `STT_*` type.
    pub kind: u8,
}

/// Something in the file that is inconsistent; the part concerned is skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfProblem {
    /// Program headers extend past the file.
    SegmentsOutOfBounds,
    /// Section headers extend past the file.
    SectionsOutOfBounds,
    /// The section name table is unusable.
    SectionNamesUnreadable,
    /// The dynamic segment extends past the file.
    DynamicOutOfBounds,
    /// The dynamic string table is unusable.
    DynamicStringsUnreadable,
    /// A symbol table extends past the file.
    SymbolsOutOfBounds,
}

/// Why a file cannot be read as ELF at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfError {
    /// No ELF magic.
    NotElf,
    /// Unknown class or byte order.
    Unsupported,
    /// The header is cut short.
    Truncated,
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotElf => "not an ELF file",
            Self::Unsupported => "unsupported ELF class or byte order",
            Self::Truncated => "ELF header is truncated",
        })
    }
}

impl std::error::Error for ElfError {}

/// A parsed ELF file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf {
    /// 32/64-bit.
    pub class: Class,
    /// Little-endian.
    pub little_endian: bool,
    /// File type.
    pub kind: ElfKind,
    /// Architecture.
    pub machine: Machine,
    /// Program headers.
    pub segments: Vec<Segment>,
    /// Section headers (empty when stripped).
    pub sections: Vec<Section>,
    /// Dynamic entries `(tag, value)` up to `DT_NULL`.
    pub dynamic: Vec<(i64, u64)>,
    /// `DT_NEEDED` libraries.
    pub needed: Vec<String>,
    /// `DT_SONAME`.
    pub soname: Option<String>,
    /// `DT_RPATH`.
    pub rpath: Option<String>,
    /// `DT_RUNPATH`.
    pub runpath: Option<String>,
    /// Dynamic symbols (imports and exports).
    pub dynamic_symbols: Vec<Symbol>,
    /// Names of `.symtab` symbols (present when not stripped).
    pub static_symbols: Vec<String>,
    /// `.comment` strings (compiler and toolchain versions).
    pub comments: Vec<String>,
    /// Inconsistencies found.
    pub problems: Vec<ElfProblem>,
}

/// Bounds-checked reads in the file's byte order and word size.
#[derive(Clone, Copy)]
struct Reader<'data> {
    bytes: &'data [u8],
    little: bool,
    class: Class,
}

impl<'data> Reader<'data> {
    fn slice(&self, offset: u64, length: u64) -> Option<&'data [u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(length).ok()?)?;
        self.bytes.get(start..end)
    }

    fn u8(&self, offset: u64) -> Option<u8> {
        self.slice(offset, 1).map(|bytes| bytes[0])
    }

    fn u16(&self, offset: u64) -> Option<u16> {
        let bytes: [u8; 2] = self.slice(offset, 2)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    fn u32(&self, offset: u64) -> Option<u32> {
        let bytes: [u8; 4] = self.slice(offset, 4)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn u64(&self, offset: u64) -> Option<u64> {
        let bytes: [u8; 8] = self.slice(offset, 8)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }

    /// An address or size: 4 bytes in ELF32, 8 in ELF64.
    fn word(&self, offset: u64) -> Option<u64> {
        match self.class {
            Class::Elf32 => self.u32(offset).map(u64::from),
            Class::Elf64 => self.u64(offset),
        }
    }

    fn word_size(&self) -> u64 {
        match self.class {
            Class::Elf32 => 4,
            Class::Elf64 => 8,
        }
    }

    /// A NUL-terminated string at `offset`, at most [`MAX_NAME_LENGTH`] bytes, within `limit`.
    fn c_string(&self, offset: u64, limit: u64) -> Option<String> {
        let start = usize::try_from(offset).ok()?;
        let end = usize::try_from(limit)
            .ok()?
            .min(self.bytes.len())
            .min(start.saturating_add(MAX_NAME_LENGTH));
        let bytes = self.bytes.get(start..end)?;
        let length = bytes
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..length]).into_owned())
    }
}

/// Header fields that locate the tables.
struct Header {
    kind: ElfKind,
    machine: Machine,
    program_offset: u64,
    program_entry_size: u64,
    program_count: u64,
    section_offset: u64,
    section_entry_size: u64,
    section_count: u64,
    section_names_index: u64,
}

impl Elf {
    /// Parses an ELF file. Only a missing magic, an unknown class or byte order, or a truncated
    /// header are errors; inconsistent tables are recorded in [`Elf::problems`] and skipped.
    pub fn parse(bytes: &[u8]) -> Result<Self, ElfError> {
        if bytes.get(..4) != Some(b"\x7fELF") {
            return Err(ElfError::NotElf);
        }
        let class = match bytes.get(4) {
            Some(1) => Class::Elf32,
            Some(2) => Class::Elf64,
            _ => return Err(ElfError::Unsupported),
        };
        let little = match bytes.get(5) {
            Some(1) => true,
            Some(2) => false,
            _ => return Err(ElfError::Unsupported),
        };
        let reader = Reader {
            bytes,
            little,
            class,
        };
        let header = read_header(&reader).ok_or(ElfError::Truncated)?;
        let mut elf = Self {
            class,
            little_endian: little,
            kind: header.kind,
            machine: header.machine,
            segments: Vec::new(),
            sections: Vec::new(),
            dynamic: Vec::new(),
            needed: Vec::new(),
            soname: None,
            rpath: None,
            runpath: None,
            dynamic_symbols: Vec::new(),
            static_symbols: Vec::new(),
            comments: Vec::new(),
            problems: Vec::new(),
        };
        elf.read_segments(&reader, &header);
        elf.read_sections(&reader, &header);
        elf.read_dynamic(&reader);
        elf.read_dynamic_symbols(&reader);
        elf.read_static_symbols(&reader);
        elf.read_comments(&reader);
        Ok(elf)
    }

    /// A dynamic entry's value.
    pub fn dynamic_value(&self, tag: i64) -> Option<u64> {
        self.dynamic
            .iter()
            .find(|(entry, _)| *entry == tag)
            .map(|(_, value)| *value)
    }

    /// The first segment of a type.
    pub fn segment(&self, kind: u32) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.kind == kind)
    }

    /// Any symbol (dynamic or static) with this name.
    pub fn has_symbol(&self, name: &str) -> bool {
        self.dynamic_symbols
            .iter()
            .any(|symbol| symbol.name == name)
            || self.static_symbols.iter().any(|symbol| symbol == name)
    }

    /// File offset of a virtual address, through the `PT_LOAD` segments. Segment offsets come
    /// from the file, so the sum is checked: an offset past `u64::MAX` is no offset.
    fn file_offset(&self, address: u64) -> Option<u64> {
        self.segments
            .iter()
            .filter(|segment| segment.kind == PT_LOAD)
            .find(|segment| address >= segment.vaddr && address - segment.vaddr < segment.file_size)
            .and_then(|segment| (address - segment.vaddr).checked_add(segment.offset))
    }

    fn read_segments(&mut self, reader: &Reader<'_>, header: &Header) {
        let minimum = match reader.class {
            Class::Elf32 => 32,
            Class::Elf64 => 56,
        };
        let fits = header.program_entry_size >= minimum
            && header
                .program_count
                .checked_mul(header.program_entry_size)
                .and_then(|length| reader.slice(header.program_offset, length))
                .is_some();
        if header.program_count > 0 && !fits {
            self.problems.push(ElfProblem::SegmentsOutOfBounds);
            return;
        }
        for index in 0..header.program_count {
            let at = header.program_offset + index * header.program_entry_size;
            if let Some(segment) = read_segment(reader, at) {
                self.segments.push(segment);
            }
        }
    }

    fn read_sections(&mut self, reader: &Reader<'_>, header: &Header) {
        let minimum = match reader.class {
            Class::Elf32 => 40,
            Class::Elf64 => 64,
        };
        let fits = header.section_entry_size >= minimum
            && header
                .section_count
                .checked_mul(header.section_entry_size)
                .and_then(|length| reader.slice(header.section_offset, length))
                .is_some();
        if header.section_count == 0 {
            return;
        }
        if !fits {
            self.problems.push(ElfProblem::SectionsOutOfBounds);
            return;
        }
        let raw: Vec<(u32, Section)> = (0..header.section_count)
            .filter_map(|index| {
                read_section(
                    reader,
                    header.section_offset + index * header.section_entry_size,
                )
            })
            .collect();
        // The name table's range comes from the file: it must lie inside it, which also keeps
        // `offset + name_offset` and `offset + size` below from overflowing.
        let names = raw
            .get(header.section_names_index as usize)
            .map(|(_, section)| (section.offset, section.size))
            .filter(|&(offset, size)| reader.slice(offset, size).is_some());
        if names.is_none() {
            self.problems.push(ElfProblem::SectionNamesUnreadable);
        }
        self.sections = raw
            .into_iter()
            .map(|(name_offset, mut section)| {
                if let Some((offset, size)) = names
                    && u64::from(name_offset) < size
                {
                    section.name = reader
                        .c_string(offset + u64::from(name_offset), offset + size)
                        .unwrap_or_default();
                }
                section
            })
            .collect();
    }

    fn read_dynamic(&mut self, reader: &Reader<'_>) {
        let Some(dynamic) = self.segment(PT_DYNAMIC).copied() else {
            return;
        };
        if reader.slice(dynamic.offset, dynamic.file_size).is_none() {
            self.problems.push(ElfProblem::DynamicOutOfBounds);
            return;
        }
        let entry_size = reader.word_size() * 2;
        let count = (dynamic.file_size / entry_size).min(MAX_DYNAMIC_ENTRIES as u64);
        for index in 0..count {
            let at = dynamic.offset + index * entry_size;
            let (Some(tag), Some(value)) = (reader.word(at), reader.word(at + reader.word_size()))
            else {
                break;
            };
            let tag = match reader.class {
                Class::Elf32 => i64::from(tag as u32 as i32),
                Class::Elf64 => tag as i64,
            };
            if tag == 0 {
                break;
            }
            self.dynamic.push((tag, value));
        }
        self.read_dynamic_strings(reader);
    }

    fn read_dynamic_strings(&mut self, reader: &Reader<'_>) {
        let table = self
            .dynamic_value(DT_STRTAB)
            .and_then(|address| self.file_offset(address));
        let size = self.dynamic_value(DT_STRSZ).unwrap_or(0);
        let Some(table) = table.filter(|&table| reader.slice(table, size).is_some()) else {
            if self
                .dynamic
                .iter()
                .any(|(tag, _)| matches!(*tag, DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH))
            {
                self.problems.push(ElfProblem::DynamicStringsUnreadable);
            }
            return;
        };
        let string = |offset: u64| {
            (offset < size)
                .then(|| reader.c_string(table + offset, table + size))
                .flatten()
        };
        for (tag, value) in self.dynamic.clone() {
            match tag {
                DT_NEEDED => self.needed.extend(string(value)),
                DT_SONAME => self.soname = string(value),
                DT_RPATH => self.rpath = string(value),
                DT_RUNPATH => self.runpath = string(value),
                _ => {}
            }
        }
    }

    /// From the `.dynsym` section when present, else from `DT_SYMTAB` with the count taken
    /// from `DT_HASH` or `DT_GNU_HASH`, as the dynamic linker sees it.
    fn read_dynamic_symbols(&mut self, reader: &Reader<'_>) {
        let entry_size = symbol_entry_size(reader.class);
        let from_section = self
            .sections
            .iter()
            .find(|section| section.kind == SHT_DYNSYM)
            .map(|section| {
                let strings = self
                    .sections
                    .get(section.link as usize)
                    .map(|strings| (strings.offset, strings.size));
                (section.offset, section.size / entry_size, strings)
            });
        let located = from_section.or_else(|| {
            let table = self.file_offset(self.dynamic_value(DT_SYMTAB)?)?;
            let strings = self.file_offset(self.dynamic_value(DT_STRTAB)?)?;
            let size = self.dynamic_value(DT_STRSZ)?;
            Some((
                table,
                self.dynamic_symbol_count(reader)?,
                Some((strings, size)),
            ))
        });
        let Some((table, count, Some((strings, strings_size)))) = located else {
            return;
        };
        if self
            .dynamic_value(DT_SYMENT)
            .is_some_and(|size| size != entry_size)
        {
            self.problems.push(ElfProblem::SymbolsOutOfBounds);
            return;
        }
        match read_symbols(reader, table, count, strings, strings_size) {
            Some(symbols) => self.dynamic_symbols = symbols,
            None => self.problems.push(ElfProblem::SymbolsOutOfBounds),
        }
    }

    fn dynamic_symbol_count(&self, reader: &Reader<'_>) -> Option<u64> {
        if let Some(hash) = self
            .dynamic_value(DT_HASH)
            .and_then(|address| self.file_offset(address))
        {
            return reader.u32(hash.checked_add(4)?).map(u64::from);
        }
        let hash = self
            .dynamic_value(DT_GNU_HASH)
            .and_then(|address| self.file_offset(address))?;
        gnu_hash_symbol_count(reader, hash)
    }

    fn read_static_symbols(&mut self, reader: &Reader<'_>) {
        let entry_size = symbol_entry_size(reader.class);
        let tables: Vec<(u64, u64, u64, u64)> = self
            .sections
            .iter()
            .filter(|section| section.kind == SHT_SYMTAB)
            .filter_map(|section| {
                let strings = self.sections.get(section.link as usize)?;
                Some((
                    section.offset,
                    section.size / entry_size,
                    strings.offset,
                    strings.size,
                ))
            })
            .collect();
        for (table, count, strings, strings_size) in tables {
            match read_symbols(reader, table, count, strings, strings_size) {
                Some(symbols) => self
                    .static_symbols
                    .extend(symbols.into_iter().map(|symbol| symbol.name)),
                None => self.problems.push(ElfProblem::SymbolsOutOfBounds),
            }
        }
    }

    fn read_comments(&mut self, reader: &Reader<'_>) {
        let Some(comment) = self
            .sections
            .iter()
            .find(|section| section.name == ".comment" && section.kind != SHT_NOBITS)
        else {
            return;
        };
        let Some(bytes) = reader.slice(comment.offset, comment.size.min(64 * 1024)) else {
            return;
        };
        self.comments = bytes
            .split(|&byte| byte == 0)
            .filter(|text| !text.is_empty())
            .take(MAX_COMMENTS)
            .map(|text| {
                String::from_utf8_lossy(&text[..text.len().min(MAX_NAME_LENGTH)]).into_owned()
            })
            .collect();
    }
}

fn read_header(reader: &Reader<'_>) -> Option<Header> {
    let kind = match reader.u16(16)? {
        1 => ElfKind::Relocatable,
        2 => ElfKind::Executable,
        3 => ElfKind::Shared,
        4 => ElfKind::Core,
        other => ElfKind::Other(other),
    };
    let machine = Machine(reader.u16(18)?);
    let (program, section, sizes) = match reader.class {
        Class::Elf32 => (28, 32, 42),
        Class::Elf64 => (32, 40, 54),
    };
    Some(Header {
        kind,
        machine,
        program_offset: reader.word(program)?,
        section_offset: reader.word(section)?,
        program_entry_size: u64::from(reader.u16(sizes)?),
        program_count: u64::from(reader.u16(sizes + 2)?),
        section_entry_size: u64::from(reader.u16(sizes + 4)?),
        section_count: u64::from(reader.u16(sizes + 6)?),
        section_names_index: u64::from(reader.u16(sizes + 8)?),
    })
}

fn read_segment(reader: &Reader<'_>, at: u64) -> Option<Segment> {
    Some(match reader.class {
        Class::Elf64 => Segment {
            kind: reader.u32(at)?,
            flags: reader.u32(at + 4)?,
            offset: reader.u64(at + 8)?,
            vaddr: reader.u64(at + 16)?,
            file_size: reader.u64(at + 32)?,
            memory_size: reader.u64(at + 40)?,
            align: reader.u64(at + 48)?,
        },
        Class::Elf32 => Segment {
            kind: reader.u32(at)?,
            offset: u64::from(reader.u32(at + 4)?),
            vaddr: u64::from(reader.u32(at + 8)?),
            file_size: u64::from(reader.u32(at + 16)?),
            memory_size: u64::from(reader.u32(at + 20)?),
            flags: reader.u32(at + 24)?,
            align: u64::from(reader.u32(at + 28)?),
        },
    })
}

/// The raw name offset and the section (name filled in later).
fn read_section(reader: &Reader<'_>, at: u64) -> Option<(u32, Section)> {
    let name = reader.u32(at)?;
    let kind = reader.u32(at + 4)?;
    let section = match reader.class {
        Class::Elf64 => Section {
            name: String::new(),
            kind,
            offset: reader.u64(at + 24)?,
            size: reader.u64(at + 32)?,
            link: reader.u32(at + 40)?,
            entry_size: reader.u64(at + 56)?,
        },
        Class::Elf32 => Section {
            name: String::new(),
            kind,
            offset: u64::from(reader.u32(at + 16)?),
            size: u64::from(reader.u32(at + 20)?),
            link: reader.u32(at + 24)?,
            entry_size: u64::from(reader.u32(at + 36)?),
        },
    };
    Some((name, section))
}

fn symbol_entry_size(class: Class) -> u64 {
    match class {
        Class::Elf32 => 16,
        Class::Elf64 => 24,
    }
}

/// Reads `count` symbols; `None` when the table or its strings fall outside the file.
fn read_symbols(
    reader: &Reader<'_>,
    table: u64,
    count: u64,
    strings: u64,
    strings_size: u64,
) -> Option<Vec<Symbol>> {
    let entry_size = symbol_entry_size(reader.class);
    let count = count.min(MAX_SYMBOLS as u64);
    reader.slice(table, count.checked_mul(entry_size)?)?;
    reader.slice(strings, strings_size)?;
    let mut symbols = Vec::with_capacity(count as usize);
    for index in 0..count {
        let at = table + index * entry_size;
        let name_offset = u64::from(reader.u32(at)?);
        let (info, section_index) = match reader.class {
            Class::Elf64 => (reader.u8(at + 4)?, reader.u16(at + 6)?),
            Class::Elf32 => (reader.u8(at + 12)?, reader.u16(at + 14)?),
        };
        let name = if name_offset < strings_size {
            reader
                .c_string(strings + name_offset, strings + strings_size)
                .unwrap_or_default()
        } else {
            String::new()
        };
        symbols.push(Symbol {
            name,
            defined: section_index != 0,
            kind: info & 0xf,
        });
    }
    Some(symbols)
}

/// Number of dynamic symbols from a GNU hash table: past the highest bucket's chain end.
/// Every offset here is derived from file values, so each sum is checked.
fn gnu_hash_symbol_count(reader: &Reader<'_>, at: u64) -> Option<u64> {
    let buckets = u64::from(reader.u32(at)?);
    let symbol_offset = u64::from(reader.u32(at.checked_add(4)?)?);
    let bloom_words = u64::from(reader.u32(at.checked_add(8)?)?);
    let bucket_start = at
        .checked_add(16)?
        .checked_add(bloom_words.checked_mul(reader.word_size())?)?;
    let chain_start = bucket_start.checked_add(buckets.checked_mul(4)?)?;
    let mut highest = 0u64;
    for bucket in 0..buckets.min(MAX_SYMBOLS as u64) {
        highest = highest.max(u64::from(
            reader.u32(bucket_start.checked_add(bucket * 4)?)?,
        ));
    }
    if highest < symbol_offset {
        return Some(symbol_offset);
    }
    let mut index = highest;
    while index - symbol_offset < MAX_SYMBOLS as u64 {
        let chain = reader.u32(chain_start.checked_add((index - symbol_offset) * 4)?)?;
        index += 1;
        if chain & 1 == 1 {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf_and_truncated_headers() {
        assert_eq!(Elf::parse(b"MZ").unwrap_err(), ElfError::NotElf);
        assert_eq!(
            Elf::parse(b"\x7fELF\x03\x01").unwrap_err(),
            ElfError::Unsupported
        );
        assert_eq!(
            Elf::parse(b"\x7fELF\x02\x01\x01").unwrap_err(),
            ElfError::Truncated
        );
    }

    #[test]
    fn machine_names() {
        assert_eq!(Machine(183).name(), "AArch64");
        assert_eq!(Machine(40).name(), "ARM");
        assert_eq!(Machine(1).name(), "other");
    }
}
