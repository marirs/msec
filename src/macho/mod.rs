//! Mach-O files (iOS and macOS executables and libraries), read with bounds checks from
//! untrusted bytes: thin images and universal ("fat") files, the header, every load command
//! msec uses, the symbol table, and the embedded code signature ([`signature`]).
//!
//! Each image is read the way `otool -l`, `nm` and `codesign -d` read it, and the tests compare
//! msec's reading with theirs on fixtures built by Xcode's toolchain
//! (`tests/fixtures/macho/build_macho.sh`). Malformed structures are recorded as
//! [`MachOAnomaly`]s; what cannot be read at all is a [`MachOError`]. No claim is made about
//! what the kernel or dyld would do with a malformed file: iOS binaries cannot be run here.
//!
//! MobSF reads Mach-O with LIEF (and `macholib`); [`Hardening`] reproduces its `MachOChecksec`
//! checks from the parsed image (see `docs/PORTING.md`).

mod hardening;
mod image;
pub mod signature;
pub mod signer;

pub use hardening::Hardening;
pub use image::{
    BuildVersion, Dylib, DylibKind, Encryption, Header, LinkeditData, MachO, Section, Segment,
    Symbols, Tool, VersionMin, command_name, full_version, platform_name, short_version,
};

/// `MH_MAGIC`: 32-bit image, the file's byte order.
pub const MH_MAGIC: u32 = 0xfeed_face;
/// `MH_MAGIC_64`: 64-bit image.
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// `FAT_MAGIC`: universal file with 32-bit offsets (always big-endian).
pub const FAT_MAGIC: u32 = 0xcafe_babe;
/// `FAT_MAGIC_64`: universal file with 64-bit offsets.
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// More architectures than this in a fat header is not a fat file: `0xcafebabe` is also the
/// magic of Java class files, whose next field (a version) is at least 45. `file(1)` uses 20.
const MAX_FAT_ARCHES: u32 = 20;

/// CPU types (`cputype`).
pub const CPU_TYPE_X86: u32 = 7;
/// 64-bit x86.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// 32-bit ARM.
pub const CPU_TYPE_ARM: u32 = 12;
/// 64-bit ARM.
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// ARM64 with 32-bit pointers (watchOS).
pub const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;

/// A Mach-O file: one image, or a universal file with one image per architecture.
#[derive(Debug, Clone, PartialEq)]
pub struct MachFile {
    /// Thin or universal.
    pub container: Container,
    /// The images: one for a thin file, one per architecture for a universal file (in header
    /// order), each read on its own.
    pub slices: Vec<Slice>,
    /// Problems in the universal header and slice table.
    pub anomalies: Vec<MachOAnomaly>,
}

/// How the file holds its images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Container {
    /// One image.
    Thin,
    /// A universal file (`FAT_MAGIC` or, with 64-bit offsets, `FAT_MAGIC_64`).
    Fat {
        /// 64-bit offsets.
        wide: bool,
    },
}

/// One architecture's image.
#[derive(Debug, Clone, PartialEq)]
pub struct Slice {
    /// Where the image starts in the file.
    pub offset: u64,
    /// Its size.
    pub size: u64,
    /// CPU type the universal header (or the image) declares.
    pub cpu_type: u32,
    /// CPU subtype, capability bits included.
    pub cpu_subtype: u32,
    /// The image, or why it could not be read.
    pub image: Result<MachO, MachOError>,
}

impl Slice {
    /// `arm64`, `arm64e`, `armv7`, `x86_64`, ...
    pub fn architecture(&self) -> String {
        architecture_name(self.cpu_type, self.cpu_subtype)
    }
}

/// Why a file or an image could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachOError {
    /// Not a Mach-O file (no known magic).
    NotMachO,
    /// Shorter than its header.
    Truncated,
    /// A big-endian image: msec reads only the little-endian images Apple platforms run.
    BigEndian,
    /// The universal header's slice table does not fit in the file.
    InvalidFatHeader(&'static str),
    /// The load commands do not fit in the image.
    LoadCommandsOutOfBounds,
}

impl std::fmt::Display for MachOError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMachO => formatter.write_str("not a Mach-O file"),
            Self::Truncated => formatter.write_str("truncated: shorter than its header"),
            Self::BigEndian => formatter.write_str("big-endian image (not read)"),
            Self::InvalidFatHeader(reason) => {
                write!(formatter, "invalid universal header: {reason}")
            }
            Self::LoadCommandsOutOfBounds => {
                formatter.write_str("load commands extend past the end of the image")
            }
        }
    }
}

impl std::error::Error for MachOError {}

/// A malformed structure in an image or universal header that did not stop reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOAnomaly {
    /// What.
    pub kind: MachOAnomalyKind,
    /// Byte offset in the image (or file, for universal header problems).
    pub offset: u64,
}

/// Kinds of [`MachOAnomaly`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachOAnomalyKind {
    /// A load command whose size is too small, unaligned, or runs past the commands' area.
    /// Reading stopped there.
    InvalidLoadCommandSize {
        /// The command.
        command: u32,
        /// Its declared size.
        size: u32,
    },
    /// `ncmds` commands did not fill `sizeofcmds` exactly.
    LoadCommandCountMismatch,
    /// A load command shorter than its own fixed fields.
    LoadCommandTooShort {
        /// The command.
        command: u32,
    },
    /// A string in a load command (dylib name, rpath) whose offset is outside the command, or
    /// that is not NUL-terminated inside it.
    InvalidCommandString {
        /// The command.
        command: u32,
    },
    /// A segment or section whose file range lies outside the image.
    RangeOutOfBounds {
        /// `__TEXT`, `__TEXT,__text`, ...
        name: String,
    },
    /// The symbol table or its strings lie outside the image; symbols were not read.
    SymbolTableOutOfBounds,
    /// A symbol's name offset is outside the string table.
    SymbolNameOutOfBounds,
    /// A linkedit data command (code signature, chained fixups, ...) points outside the image.
    LinkeditDataOutOfBounds {
        /// The command.
        command: u32,
    },
    /// A command msec reads appears more than once (only the first is used).
    DuplicateCommand {
        /// The command.
        command: u32,
    },
    /// Two universal-file slices overlap.
    OverlappingSlices,
    /// A universal-file slice is not aligned as its header declares.
    MisalignedSlice,
    /// Two universal-file slices have the same CPU type and subtype.
    DuplicateArchitecture,
    /// A slice's image declares a different CPU type than the universal header.
    ArchitectureMismatch,
    /// A universal file inside a universal file.
    NestedUniversal,
}

/// Reads a thin or universal Mach-O file.
pub fn parse(data: &[u8]) -> Result<MachFile, MachOError> {
    let magic_be = read_u32_be(data, 0).ok_or(MachOError::Truncated)?;
    match magic_be {
        FAT_MAGIC | FAT_MAGIC_64 => {
            let count = read_u32_be(data, 4).ok_or(MachOError::Truncated)?;
            // 0xcafebabe followed by a large number is a Java class file, not a fat file.
            if count > MAX_FAT_ARCHES {
                return Err(MachOError::NotMachO);
            }
            parse_fat(data, magic_be == FAT_MAGIC_64, count)
        }
        _ => {
            let image = MachO::parse(data)?;
            Ok(MachFile {
                container: Container::Thin,
                slices: vec![Slice {
                    offset: 0,
                    size: data.len() as u64,
                    cpu_type: image.header.cpu_type,
                    cpu_subtype: image.header.cpu_subtype,
                    image: Ok(image),
                }],
                anomalies: Vec::new(),
            })
        }
    }
}

/// Whether the bytes start like a Mach-O file (thin or universal), for inventories.
pub fn is_macho(data: &[u8]) -> bool {
    match read_u32_be(data, 0) {
        Some(FAT_MAGIC | FAT_MAGIC_64) => read_u32_be(data, 4).is_some_and(|n| n <= MAX_FAT_ARCHES),
        Some(_) => matches!(read_u32_le(data, 0), Some(MH_MAGIC | MH_MAGIC_64)),
        None => false,
    }
}

fn parse_fat(data: &[u8], wide: bool, count: u32) -> Result<MachFile, MachOError> {
    let entry_size: usize = if wide { 32 } else { 20 };
    let table_end = 8 + count as usize * entry_size;
    if data.len() < table_end {
        return Err(MachOError::InvalidFatHeader(
            "slice table past the end of the file",
        ));
    }
    let mut anomalies = Vec::new();
    let mut slices: Vec<Slice> = Vec::new();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for index in 0..count as usize {
        let at = 8 + index * entry_size;
        let field = |offset: usize| read_u32_be(data, at + offset).expect("inside the table");
        let wide_field = |offset: usize| read_u64_be(data, at + offset).expect("inside the table");
        let (cpu_type, cpu_subtype) = (field(0), field(4));
        let (offset, size, align) = if wide {
            (wide_field(8), wide_field(16), field(24))
        } else {
            (u64::from(field(8)), u64::from(field(12)), field(16))
        };
        let in_file = offset
            .checked_add(size)
            .is_some_and(|end| offset >= table_end as u64 && end <= data.len() as u64);
        if align < 64 && !offset.is_multiple_of(1u64 << align) {
            anomalies.push(MachOAnomaly {
                kind: MachOAnomalyKind::MisalignedSlice,
                offset: at as u64,
            });
        }
        if slices
            .iter()
            .any(|slice| slice.cpu_type == cpu_type && slice.cpu_subtype == cpu_subtype)
        {
            anomalies.push(MachOAnomaly {
                kind: MachOAnomalyKind::DuplicateArchitecture,
                offset: at as u64,
            });
        }
        if in_file
            && ranges
                .iter()
                .any(|(start, end)| offset < *end && *start < offset + size)
        {
            anomalies.push(MachOAnomaly {
                kind: MachOAnomalyKind::OverlappingSlices,
                offset: at as u64,
            });
        }
        let image = if in_file {
            ranges.push((offset, offset + size));
            let bytes = &data[offset as usize..(offset + size) as usize];
            if matches!(read_u32_be(bytes, 0), Some(FAT_MAGIC | FAT_MAGIC_64)) {
                anomalies.push(MachOAnomaly {
                    kind: MachOAnomalyKind::NestedUniversal,
                    offset: at as u64,
                });
                Err(MachOError::NotMachO)
            } else {
                MachO::parse(bytes)
            }
        } else {
            Err(MachOError::InvalidFatHeader("slice outside the file"))
        };
        if let Ok(image) = &image
            && image.header.cpu_type != cpu_type
        {
            anomalies.push(MachOAnomaly {
                kind: MachOAnomalyKind::ArchitectureMismatch,
                offset: at as u64,
            });
        }
        slices.push(Slice {
            offset,
            size,
            cpu_type,
            cpu_subtype,
            image,
        });
    }
    Ok(MachFile {
        container: Container::Fat { wide },
        slices,
        anomalies,
    })
}

/// `arm64`, `arm64e`, `armv7`, `armv7s`, `x86_64`, `i386`, `arm64_32`, or the numbers.
pub fn architecture_name(cpu_type: u32, cpu_subtype: u32) -> String {
    let subtype = cpu_subtype & 0x00ff_ffff;
    match (cpu_type, subtype) {
        (CPU_TYPE_ARM64, 2) => "arm64e".to_owned(),
        (CPU_TYPE_ARM64, _) => "arm64".to_owned(),
        (CPU_TYPE_ARM64_32, _) => "arm64_32".to_owned(),
        (CPU_TYPE_ARM, 9) => "armv7".to_owned(),
        (CPU_TYPE_ARM, 11) => "armv7s".to_owned(),
        (CPU_TYPE_ARM, 12) => "armv7k".to_owned(),
        (CPU_TYPE_ARM, _) => "arm".to_owned(),
        (CPU_TYPE_X86_64, _) => "x86_64".to_owned(),
        (CPU_TYPE_X86, _) => "i386".to_owned(),
        _ => format!("cputype {cpu_type:#x} subtype {cpu_subtype:#x}"),
    }
}

pub(crate) fn read_u32_be(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn read_u64_be(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

pub(crate) fn read_u32_le(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn read_u64_le(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}
