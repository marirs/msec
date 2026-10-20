//! One Mach-O image: header, load commands, symbol table, code signature.

use super::signature::{self, CodeSignature, SignatureError};
use super::{
    MH_MAGIC, MH_MAGIC_64, MachOAnomaly, MachOAnomalyKind, MachOError, read_u32_le, read_u64_le,
};

/// Header flags.
const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;
const MH_PIE: u32 = 0x20_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x100_0000;
const MH_APP_EXTENSION_SAFE: u32 = 0x200_0000;

/// `LC_REQ_DYLD`: dyld must understand the command.
const LC_REQ_DYLD: u32 = 0x8000_0000;
/// Load commands msec reads.
pub(crate) const LC_SEGMENT: u32 = 0x1;
pub(crate) const LC_SYMTAB: u32 = 0x2;
pub(crate) const LC_LOAD_DYLIB: u32 = 0xc;
pub(crate) const LC_ID_DYLIB: u32 = 0xd;
pub(crate) const LC_LOAD_DYLINKER: u32 = 0xe;
pub(crate) const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub(crate) const LC_SEGMENT_64: u32 = 0x19;
pub(crate) const LC_UUID: u32 = 0x1b;
pub(crate) const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub(crate) const LC_CODE_SIGNATURE: u32 = 0x1d;
pub(crate) const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub(crate) const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub(crate) const LC_ENCRYPTION_INFO: u32 = 0x21;
pub(crate) const LC_DYLD_INFO: u32 = 0x22;
pub(crate) const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub(crate) const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub(crate) const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub(crate) const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub(crate) const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub(crate) const LC_SOURCE_VERSION: u32 = 0x2a;
pub(crate) const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub(crate) const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub(crate) const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub(crate) const LC_BUILD_VERSION: u32 = 0x32;
pub(crate) const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub(crate) const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

/// Symbol type bits (`nlist.n_type`).
const N_STAB: u8 = 0xe0;
/// `N_OPT`: ld64 puts one in every image (`radr://5614542`); it is not debug information.
const N_OPT: u8 = 0x3c;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x0;
/// Section types without file contents.
const ZEROFILL_TYPES: [u32; 3] = [0x1, 0xc, 0x12];
/// Longest symbol name read; Swift's mangled names run to a few kilobytes.
const MAX_SYMBOL_NAME: usize = 64 * 1024;

/// A Mach-O image.
#[derive(Debug, Clone, PartialEq)]
pub struct MachO {
    /// The header.
    pub header: Header,
    /// Every load command's `cmd`, in order.
    pub load_commands: Vec<u32>,
    /// `LC_SEGMENT(_64)`s with their sections.
    pub segments: Vec<Segment>,
    /// Libraries the image links (`LC_LOAD_DYLIB` and its weak, re-export, lazy and upward
    /// variants), in order.
    pub dylibs: Vec<Dylib>,
    /// `LC_ID_DYLIB`: the library's own install name.
    pub id_dylib: Option<Dylib>,
    /// `LC_LOAD_DYLINKER`.
    pub dylinker: Option<String>,
    /// `LC_RPATH` search paths, in order.
    pub rpaths: Vec<String>,
    /// `LC_BUILD_VERSION`.
    pub build_version: Option<BuildVersion>,
    /// `LC_VERSION_MIN_*` (older toolchains).
    pub version_min: Option<VersionMin>,
    /// `LC_UUID`.
    pub uuid: Option<[u8; 16]>,
    /// `LC_MAIN`: the entry point's file offset.
    pub entry_offset: Option<u64>,
    /// `LC_SOURCE_VERSION`, as `A.B.C.D.E`.
    pub source_version: Option<String>,
    /// `LC_ENCRYPTION_INFO(_64)`.
    pub encryption: Option<Encryption>,
    /// `LC_CODE_SIGNATURE`.
    pub code_signature: Option<LinkeditData>,
    /// `LC_DYLD_CHAINED_FIXUPS`.
    pub chained_fixups: Option<LinkeditData>,
    /// `LC_DYLD_EXPORTS_TRIE`.
    pub exports_trie: Option<LinkeditData>,
    /// `LC_DYLD_INFO(_ONLY)` is present (classic binding information).
    pub dyld_info: bool,
    /// The symbol table, when there is one and it lies inside the image.
    pub symbols: Option<Symbols>,
    /// The embedded code signature, when `LC_CODE_SIGNATURE` points inside the image.
    pub signature: Option<Result<CodeSignature, SignatureError>>,
    /// Malformed structures that did not stop reading.
    pub anomalies: Vec<MachOAnomaly>,
}

/// The `mach_header(_64)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    /// 64-bit image.
    pub is_64: bool,
    /// `cputype`.
    pub cpu_type: u32,
    /// `cpusubtype`.
    pub cpu_subtype: u32,
    /// `filetype` (2 executable, 6 dylib, 8 bundle, ...).
    pub file_type: u32,
    /// `ncmds`.
    pub command_count: u32,
    /// `sizeofcmds`.
    pub commands_size: u32,
    /// `flags`.
    pub flags: u32,
}

impl Header {
    /// `MH_PIE`: the executable is loaded at a random address.
    pub fn is_pie(&self) -> bool {
        self.flags & MH_PIE != 0
    }

    /// `MH_ALLOW_STACK_EXECUTION`: the stack is executable.
    pub fn allows_stack_execution(&self) -> bool {
        self.flags & MH_ALLOW_STACK_EXECUTION != 0
    }

    /// `MH_NO_HEAP_EXECUTION`.
    pub fn no_heap_execution(&self) -> bool {
        self.flags & MH_NO_HEAP_EXECUTION != 0
    }

    /// `MH_APP_EXTENSION_SAFE`.
    pub fn app_extension_safe(&self) -> bool {
        self.flags & MH_APP_EXTENSION_SAFE != 0
    }

    /// `MH_EXECUTE`.
    pub fn is_executable(&self) -> bool {
        self.file_type == 2
    }

    /// `executable`, `dylib`, `bundle`, ... for messages.
    pub fn file_type_name(&self) -> &'static str {
        match self.file_type {
            1 => "object",
            2 => "executable",
            6 => "dylib",
            7 => "dylinker",
            8 => "bundle",
            9 => "dylib stub",
            10 => "dSYM",
            11 => "kext bundle",
            12 => "fileset",
            _ => "unknown",
        }
    }
}

/// A segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// `__TEXT`, `__DATA`, `__LINKEDIT`, ...
    pub name: String,
    /// Virtual address.
    pub vm_address: u64,
    /// Virtual size.
    pub vm_size: u64,
    /// File offset.
    pub file_offset: u64,
    /// File size.
    pub file_size: u64,
    /// `maxprot`.
    pub max_protection: u32,
    /// `initprot`.
    pub initial_protection: u32,
    /// `flags`.
    pub flags: u32,
    /// Its sections.
    pub sections: Vec<Section>,
}

/// A section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// `__text`, `__cstring`, ...
    pub name: String,
    /// The segment it names.
    pub segment: String,
    /// Address.
    pub address: u64,
    /// Size.
    pub size: u64,
    /// File offset (0 for zero-fill sections).
    pub offset: u32,
    /// `flags` (type in the low byte).
    pub flags: u32,
}

/// A linked library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dylib {
    /// How it is linked.
    pub kind: DylibKind,
    /// Install name (`@rpath/Lib.framework/Lib`).
    pub name: String,
    /// `current_version` (`A.B.C` packed).
    pub current_version: u32,
    /// `compatibility_version`.
    pub compatibility_version: u32,
}

/// The load command that names a library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DylibKind {
    /// `LC_LOAD_DYLIB`.
    Load,
    /// `LC_LOAD_WEAK_DYLIB`: missing is allowed.
    Weak,
    /// `LC_REEXPORT_DYLIB`.
    Reexport,
    /// `LC_LAZY_LOAD_DYLIB`.
    Lazy,
    /// `LC_LOAD_UPWARD_DYLIB`.
    Upward,
    /// `LC_ID_DYLIB`.
    Id,
}

/// `LC_BUILD_VERSION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildVersion {
    /// Platform (1 macOS, 2 iOS, 3 tvOS, 4 watchOS, 6 Mac Catalyst, 7 iOS simulator, 11
    /// visionOS, ...).
    pub platform: u32,
    /// Minimum OS version (`A.B.C` packed).
    pub minimum_os: u32,
    /// SDK version.
    pub sdk: u32,
    /// Tools that built it.
    pub tools: Vec<Tool>,
}

impl BuildVersion {
    /// `iOS`, `iOS Simulator`, `macOS`, ...
    pub fn platform_name(&self) -> String {
        platform_name(self.platform)
    }
}

/// A tool in `LC_BUILD_VERSION` (3 ld, 1 clang, 2 swift).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tool {
    /// Tool number.
    pub tool: u32,
    /// Its version (`A.B.C` packed).
    pub version: u32,
}

/// `LC_VERSION_MIN_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionMin {
    /// The command (which platform).
    pub command: u32,
    /// Minimum OS version.
    pub version: u32,
    /// SDK version.
    pub sdk: u32,
}

/// `LC_ENCRYPTION_INFO(_64)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encryption {
    /// `cryptoff`.
    pub offset: u32,
    /// `cryptsize`.
    pub size: u32,
    /// `cryptid`: non-zero when the range is encrypted (FairPlay, App Store downloads).
    pub id: u32,
}

impl Encryption {
    /// The range is encrypted.
    pub fn encrypted(&self) -> bool {
        self.id != 0
    }
}

/// A `linkedit_data_command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkeditData {
    /// `dataoff`, from the image start.
    pub offset: u32,
    /// `datasize`.
    pub size: u32,
}

/// What the symbol table holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Symbols {
    /// Entries (`nsyms`).
    pub count: usize,
    /// Undefined external symbols (imports), sorted and unique, as `nm -u` lists them.
    pub imports: Vec<String>,
    /// Defined external symbols.
    pub exported: usize,
    /// Local (non-external, non-debug) symbols.
    pub local: usize,
    /// Debugging entries (`N_STAB`, except ld64's `N_OPT` marker): present when the image was
    /// not stripped of its debug map.
    pub debug: usize,
}

impl MachO {
    /// Reads one image (a thin file, or one slice of a universal file).
    pub fn parse(data: &[u8]) -> Result<Self, MachOError> {
        let magic = read_u32_le(data, 0).ok_or(MachOError::Truncated)?;
        let is_64 = match magic {
            MH_MAGIC_64 => true,
            MH_MAGIC => false,
            _ if matches!(magic.swap_bytes(), MH_MAGIC | MH_MAGIC_64) => {
                return Err(MachOError::BigEndian);
            }
            _ => return Err(MachOError::NotMachO),
        };
        let header_size = if is_64 { 32 } else { 28 };
        if data.len() < header_size {
            return Err(MachOError::Truncated);
        }
        let field = |index: usize| read_u32_le(data, 4 + index * 4).expect("inside the header");
        let header = Header {
            is_64,
            cpu_type: field(0),
            cpu_subtype: field(1),
            file_type: field(2),
            command_count: field(3),
            commands_size: field(4),
            flags: field(5),
        };
        let commands_end = header_size
            .checked_add(header.commands_size as usize)
            .filter(|end| *end <= data.len())
            .ok_or(MachOError::LoadCommandsOutOfBounds)?;
        let mut image = MachO {
            header,
            load_commands: Vec::new(),
            segments: Vec::new(),
            dylibs: Vec::new(),
            id_dylib: None,
            dylinker: None,
            rpaths: Vec::new(),
            build_version: None,
            version_min: None,
            uuid: None,
            entry_offset: None,
            source_version: None,
            encryption: None,
            code_signature: None,
            chained_fixups: None,
            exports_trie: None,
            dyld_info: false,
            symbols: None,
            signature: None,
            anomalies: Vec::new(),
        };
        image.read_commands(data, header_size, commands_end);
        image.signature = image.code_signature.map(|linkedit| {
            signature::parse(&data[linkedit.offset as usize..][..linkedit.size as usize])
        });
        Ok(image)
    }

    fn anomaly(&mut self, kind: MachOAnomalyKind, offset: usize) {
        self.anomalies.push(MachOAnomaly {
            kind,
            offset: offset as u64,
        });
    }

    fn read_commands(&mut self, data: &[u8], start: usize, end: usize) {
        let alignment = if self.header.is_64 { 8 } else { 4 };
        let mut at = start;
        let mut read = 0u32;
        while read < self.header.command_count {
            // More commands declared than `sizeofcmds` holds.
            if at + 8 > end {
                self.anomaly(MachOAnomalyKind::LoadCommandCountMismatch, at);
                return;
            }
            let command = read_u32_le(data, at).expect("inside the commands");
            let size = read_u32_le(data, at + 4).expect("inside the commands");
            let fits = (size as usize) >= 8 && at + size as usize <= end;
            if !fits || !size.is_multiple_of(alignment) {
                self.anomaly(
                    MachOAnomalyKind::InvalidLoadCommandSize { command, size },
                    at,
                );
                if !fits {
                    return;
                }
            }
            let bytes = &data[at..at + size as usize];
            self.load_commands.push(command);
            self.read_command(data, command, bytes, at);
            at += size as usize;
            read += 1;
        }
        if at != end {
            self.anomaly(MachOAnomalyKind::LoadCommandCountMismatch, at);
        }
    }

    fn read_command(&mut self, data: &[u8], command: u32, bytes: &[u8], at: usize) {
        let short = |needed: usize| bytes.len() < needed;
        let word = |offset: usize| read_u32_le(bytes, offset).unwrap_or(0);
        let minimum = match command {
            LC_SEGMENT_64 => 72,
            LC_SEGMENT => 56,
            LC_SYMTAB => 24,
            LC_UUID => 24,
            LC_BUILD_VERSION => 24,
            LC_MAIN => 24,
            LC_SOURCE_VERSION => 16,
            LC_ENCRYPTION_INFO => 20,
            LC_ENCRYPTION_INFO_64 => 24,
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
            | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => 24,
            LC_CODE_SIGNATURE | LC_DYLD_CHAINED_FIXUPS | LC_DYLD_EXPORTS_TRIE => 16,
            LC_RPATH | LC_LOAD_DYLINKER => 12,
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => 16,
            _ => 8,
        };
        if short(minimum) {
            self.anomaly(MachOAnomalyKind::LoadCommandTooShort { command }, at);
            return;
        }
        match command {
            LC_SEGMENT_64 | LC_SEGMENT => self.read_segment(data, command, bytes, at),
            LC_SYMTAB => self.read_symbols(data, bytes, at),
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
            | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                let Some(name) = self.command_string(command, bytes, 8, at) else {
                    return;
                };
                let dylib = Dylib {
                    kind: match command {
                        LC_LOAD_WEAK_DYLIB => DylibKind::Weak,
                        LC_REEXPORT_DYLIB => DylibKind::Reexport,
                        LC_LAZY_LOAD_DYLIB => DylibKind::Lazy,
                        LC_LOAD_UPWARD_DYLIB => DylibKind::Upward,
                        LC_ID_DYLIB => DylibKind::Id,
                        _ => DylibKind::Load,
                    },
                    name,
                    current_version: word(16),
                    compatibility_version: word(20),
                };
                if command == LC_ID_DYLIB {
                    self.first(command, at, |image| &mut image.id_dylib, dylib);
                } else {
                    self.dylibs.push(dylib);
                }
            }
            LC_LOAD_DYLINKER => {
                if let Some(name) = self.command_string(command, bytes, 8, at) {
                    self.first(command, at, |image| &mut image.dylinker, name);
                }
            }
            LC_RPATH => {
                if let Some(path) = self.command_string(command, bytes, 8, at) {
                    self.rpaths.push(path);
                }
            }
            LC_UUID => {
                let uuid: [u8; 16] = bytes[8..24].try_into().expect("checked length");
                self.first(command, at, |image| &mut image.uuid, uuid);
            }
            LC_BUILD_VERSION => {
                let tool_count = word(20) as usize;
                let tools = (0..tool_count)
                    .map_while(|index| {
                        let offset = 24 + index * 8;
                        Some(Tool {
                            tool: read_u32_le(bytes, offset)?,
                            version: read_u32_le(bytes, offset + 4)?,
                        })
                    })
                    .collect();
                let version = BuildVersion {
                    platform: word(8),
                    minimum_os: word(12),
                    sdk: word(16),
                    tools,
                };
                self.first(command, at, |image| &mut image.build_version, version);
            }
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => {
                let version = VersionMin {
                    command,
                    version: word(8),
                    sdk: word(12),
                };
                self.first(command, at, |image| &mut image.version_min, version);
            }
            LC_MAIN => {
                let offset = read_u64_le(bytes, 8).expect("checked length");
                self.first(command, at, |image| &mut image.entry_offset, offset);
            }
            LC_SOURCE_VERSION => {
                let packed = read_u64_le(bytes, 8).expect("checked length");
                let version = format!(
                    "{}.{}.{}.{}.{}",
                    packed >> 40,
                    (packed >> 30) & 0x3ff,
                    (packed >> 20) & 0x3ff,
                    (packed >> 10) & 0x3ff,
                    packed & 0x3ff
                );
                self.first(command, at, |image| &mut image.source_version, version);
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                let encryption = Encryption {
                    offset: word(8),
                    size: word(12),
                    id: word(16),
                };
                self.first(command, at, |image| &mut image.encryption, encryption);
            }
            LC_CODE_SIGNATURE | LC_DYLD_CHAINED_FIXUPS | LC_DYLD_EXPORTS_TRIE => {
                let linkedit = LinkeditData {
                    offset: word(8),
                    size: word(12),
                };
                let inside = (linkedit.offset as usize)
                    .checked_add(linkedit.size as usize)
                    .is_some_and(|end| end <= data.len());
                if !inside {
                    self.anomaly(MachOAnomalyKind::LinkeditDataOutOfBounds { command }, at);
                    return;
                }
                let slot: fn(&mut MachO) -> &mut Option<LinkeditData> = match command {
                    LC_CODE_SIGNATURE => |image| &mut image.code_signature,
                    LC_DYLD_CHAINED_FIXUPS => |image| &mut image.chained_fixups,
                    _ => |image| &mut image.exports_trie,
                };
                self.first(command, at, slot, linkedit);
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => self.dyld_info = true,
            _ => {}
        }
    }

    /// Keeps the first of a command msec reads once; a repeat is an anomaly.
    fn first<T>(
        &mut self,
        command: u32,
        at: usize,
        slot: impl FnOnce(&mut MachO) -> &mut Option<T>,
        value: T,
    ) {
        let place = slot(self);
        if place.is_some() {
            self.anomaly(MachOAnomalyKind::DuplicateCommand { command }, at);
        } else {
            *place = Some(value);
        }
    }

    /// The `lc_str` at `field`: an offset from the command's start to a NUL-terminated string
    /// inside the command.
    fn command_string(
        &mut self,
        command: u32,
        bytes: &[u8],
        field: usize,
        at: usize,
    ) -> Option<String> {
        let offset = read_u32_le(bytes, field)? as usize;
        let text = bytes
            .get(offset..)
            .filter(|_| offset >= field + 4)
            .and_then(|rest| {
                rest.iter()
                    .position(|byte| *byte == 0)
                    .map(|end| &rest[..end])
            });
        match text {
            Some(text) => Some(String::from_utf8_lossy(text).into_owned()),
            None => {
                self.anomaly(MachOAnomalyKind::InvalidCommandString { command }, at);
                None
            }
        }
    }

    fn read_segment(&mut self, data: &[u8], command: u32, bytes: &[u8], at: usize) {
        let wide = command == LC_SEGMENT_64;
        let name = fixed_name(&bytes[8..24]);
        let number = |offset: usize| -> u64 {
            if wide {
                read_u64_le(bytes, offset).unwrap_or(0)
            } else {
                u64::from(read_u32_le(bytes, offset).unwrap_or(0))
            }
        };
        let (fields, section_size) = if wide { (24, 80) } else { (24, 68) };
        let step = if wide { 8 } else { 4 };
        let vm_address = number(fields);
        let vm_size = number(fields + step);
        let file_offset = number(fields + 2 * step);
        let file_size = number(fields + 3 * step);
        let tail = fields + 4 * step;
        let max_protection = read_u32_le(bytes, tail).unwrap_or(0);
        let initial_protection = read_u32_le(bytes, tail + 4).unwrap_or(0);
        let section_count = read_u32_le(bytes, tail + 8).unwrap_or(0) as usize;
        let flags = read_u32_le(bytes, tail + 12).unwrap_or(0);
        let sections_start = tail + 16;
        if file_offset
            .checked_add(file_size)
            .is_none_or(|end| end > data.len() as u64)
        {
            self.anomaly(
                MachOAnomalyKind::RangeOutOfBounds { name: name.clone() },
                at,
            );
        }
        // Sections that do not fit in the command are not read (the count is a claim).
        let fitting = (bytes.len() - sections_start.min(bytes.len())) / section_size;
        if section_count > fitting {
            self.anomaly(MachOAnomalyKind::LoadCommandTooShort { command }, at);
        }
        let mut sections = Vec::new();
        for index in 0..section_count.min(fitting) {
            let base = sections_start + index * section_size;
            let section_bytes = &bytes[base..base + section_size];
            let value = |offset: usize| -> u64 {
                if wide {
                    read_u64_le(section_bytes, offset).unwrap_or(0)
                } else {
                    u64::from(read_u32_le(section_bytes, offset).unwrap_or(0))
                }
            };
            let address = value(32);
            let size = value(32 + step);
            let after = 32 + 2 * step;
            let section = Section {
                name: fixed_name(&section_bytes[0..16]),
                segment: fixed_name(&section_bytes[16..32]),
                address,
                size,
                offset: read_u32_le(section_bytes, after).unwrap_or(0),
                flags: read_u32_le(section_bytes, after + 16).unwrap_or(0),
            };
            let zerofill = ZEROFILL_TYPES.contains(&(section.flags & 0xff));
            if !zerofill
                && u64::from(section.offset)
                    .checked_add(section.size)
                    .is_none_or(|end| end > data.len() as u64)
            {
                self.anomaly(
                    MachOAnomalyKind::RangeOutOfBounds {
                        name: format!("{},{}", section.segment, section.name),
                    },
                    at,
                );
            }
            sections.push(section);
        }
        self.segments.push(Segment {
            name,
            vm_address,
            vm_size,
            file_offset,
            file_size,
            max_protection,
            initial_protection,
            flags,
            sections,
        });
    }

    fn read_symbols(&mut self, data: &[u8], bytes: &[u8], at: usize) {
        if self.symbols.is_some() {
            self.anomaly(
                MachOAnomalyKind::DuplicateCommand { command: LC_SYMTAB },
                at,
            );
            return;
        }
        let word = |offset: usize| read_u32_le(bytes, offset).unwrap_or(0) as usize;
        let (symbol_offset, count, string_offset, string_size) =
            (word(8), word(12), word(16), word(20));
        let entry_size = if self.header.is_64 { 16 } else { 12 };
        let table_fits = count
            .checked_mul(entry_size)
            .and_then(|size| symbol_offset.checked_add(size))
            .is_some_and(|end| end <= data.len());
        let strings_fit = string_offset
            .checked_add(string_size)
            .is_some_and(|end| end <= data.len());
        if !table_fits || !strings_fit {
            self.anomaly(MachOAnomalyKind::SymbolTableOutOfBounds, at);
            return;
        }
        let strings = &data[string_offset..string_offset + string_size];
        let mut symbols = Symbols {
            count,
            ..Symbols::default()
        };
        let mut imports = Vec::new();
        let mut bad_name = false;
        for index in 0..count {
            let entry = &data[symbol_offset + index * entry_size..][..entry_size];
            let name_offset = read_u32_le(entry, 0).expect("entry") as usize;
            let kind = entry[4];
            if kind & N_STAB != 0 {
                if kind != N_OPT {
                    symbols.debug += 1;
                }
                continue;
            }
            let external = kind & N_EXT != 0;
            let undefined = kind & N_TYPE == N_UNDF;
            // Common symbols are N_UNDF with a value; they are definitions, not imports.
            let value = if self.header.is_64 {
                read_u64_le(entry, 8).expect("entry")
            } else {
                u64::from(read_u32_le(entry, 8).expect("entry"))
            };
            match (external, undefined && value == 0) {
                (true, true) => {
                    let Some(name) = symbol_name(strings, name_offset) else {
                        bad_name = true;
                        continue;
                    };
                    imports.push(name);
                }
                (true, false) => symbols.exported += 1,
                (false, _) => symbols.local += 1,
            }
        }
        if bad_name {
            self.anomaly(MachOAnomalyKind::SymbolNameOutOfBounds, at);
        }
        imports.sort();
        imports.dedup();
        symbols.imports = imports;
        self.symbols = Some(symbols);
    }

    /// The segment named `name`.
    pub fn segment(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|segment| segment.name == name)
    }

    /// The symbol is imported (`_objc_release`, `___stack_chk_fail`).
    pub fn imports(&self, symbol: &str) -> bool {
        self.symbols.as_ref().is_some_and(|symbols| {
            symbols
                .imports
                .binary_search_by(|name| name.as_str().cmp(symbol))
                .is_ok()
        })
    }
}

/// A NUL-padded fixed-length name (`segname`, `sectname`).
fn fixed_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A symbol's name from the string table, `None` when the offset is outside it.
fn symbol_name(strings: &[u8], offset: usize) -> Option<String> {
    let rest = strings.get(offset..)?;
    let end = rest
        .iter()
        .take(MAX_SYMBOL_NAME)
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len().min(MAX_SYMBOL_NAME));
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// `17.0`, `17.0.1`: an `A.B.C` packed version as `otool` prints build versions (patch only
/// when not zero).
pub fn short_version(packed: u32) -> String {
    let (major, minor, patch) = (packed >> 16, (packed >> 8) & 0xff, packed & 0xff);
    if patch == 0 {
        format!("{major}.{minor}")
    } else {
        format!("{major}.{minor}.{patch}")
    }
}

/// `1.0.0`: an `A.B.C` packed version as `otool -L` prints library versions.
pub fn full_version(packed: u32) -> String {
    format!(
        "{}.{}.{}",
        packed >> 16,
        (packed >> 8) & 0xff,
        packed & 0xff
    )
}

/// `iOS`, `iOS Simulator`, `macOS`, ... for an `LC_BUILD_VERSION` platform.
pub fn platform_name(platform: u32) -> String {
    match platform {
        1 => "macOS".to_owned(),
        2 => "iOS".to_owned(),
        3 => "tvOS".to_owned(),
        4 => "watchOS".to_owned(),
        5 => "bridgeOS".to_owned(),
        6 => "Mac Catalyst".to_owned(),
        7 => "iOS Simulator".to_owned(),
        8 => "tvOS Simulator".to_owned(),
        9 => "watchOS Simulator".to_owned(),
        10 => "DriverKit".to_owned(),
        11 => "visionOS".to_owned(),
        12 => "visionOS Simulator".to_owned(),
        other => format!("platform {other}"),
    }
}

/// A load command's name as `otool -l` prints it (`LC_SEGMENT_64`), or its number in hex.
pub fn command_name(command: u32) -> String {
    let name = match command {
        0x1 => "LC_SEGMENT",
        0x2 => "LC_SYMTAB",
        0x3 => "LC_SYMSEG",
        0x4 => "LC_THREAD",
        0x5 => "LC_UNIXTHREAD",
        0x6 => "LC_LOADFVMLIB",
        0x7 => "LC_IDFVMLIB",
        0x8 => "LC_IDENT",
        0x9 => "LC_FVMFILE",
        0xa => "LC_PREPAGE",
        0xb => "LC_DYSYMTAB",
        0xc => "LC_LOAD_DYLIB",
        0xd => "LC_ID_DYLIB",
        0xe => "LC_LOAD_DYLINKER",
        0xf => "LC_ID_DYLINKER",
        0x10 => "LC_PREBOUND_DYLIB",
        0x11 => "LC_ROUTINES",
        0x12 => "LC_SUB_FRAMEWORK",
        0x13 => "LC_SUB_UMBRELLA",
        0x14 => "LC_SUB_CLIENT",
        0x15 => "LC_SUB_LIBRARY",
        0x16 => "LC_TWOLEVEL_HINTS",
        0x17 => "LC_PREBIND_CKSUM",
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
        0x19 => "LC_SEGMENT_64",
        0x1a => "LC_ROUTINES_64",
        0x1b => "LC_UUID",
        LC_RPATH => "LC_RPATH",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        LC_LOAD_UPWARD_DYLIB => "LC_LOAD_UPWARD_DYLIB",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        LC_MAIN => "LC_MAIN",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2b => "LC_DYLIB_CODE_SIGN_DRS",
        0x2c => "LC_ENCRYPTION_INFO_64",
        0x2d => "LC_LINKER_OPTION",
        0x2e => "LC_LINKER_OPTIMIZATION_HINT",
        0x2f => "LC_VERSION_MIN_TVOS",
        0x30 => "LC_VERSION_MIN_WATCHOS",
        0x31 => "LC_NOTE",
        0x32 => "LC_BUILD_VERSION",
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        0x8000_0035 => "LC_FILESET_ENTRY",
        0x36 => "LC_ATOM_INFO",
        _ => return format!("{command:#x}"),
    };
    name.to_owned()
}
