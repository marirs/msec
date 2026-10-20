//! Native libraries in an APK and their hardening (MobSF `elf.py::ELFChecksec`), plus the
//! Android-specific layout facts MobSF does not check: text relocations, debug sections,
//! 16 KB page-size compatibility, and ZIP alignment of uncompressed libraries.

use std::io::{Read, Seek};

use crate::archive::ZipArchive;
use crate::elf::{
    Class, DF_1_NOW, DF_BIND_NOW, DF_TEXTREL, DT_BIND_NOW, DT_DEBUG, DT_FLAGS, DT_FLAGS_1,
    DT_TEXTREL, Elf, ElfError, ElfKind, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD,
};

/// Symbols that show a stack protector is in use.
const CANARY_SYMBOLS: [&str; 2] = ["__stack_chk_fail", "__intel_security_cookie"];
/// Symbols of Dart AOT snapshots (Flutter): stack canaries, RELRO and fortify do not apply.
const DART_SYMBOLS: [&str; 2] = ["_kDartVmSnapshotInstructions", "Dart_Cleanup"];

/// How position-independent the code is (MobSF's classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PieKind {
    /// Position-independent executable (`ET_DYN` with `DT_DEBUG`).
    Pie,
    /// Shared object built as position-independent code.
    Dso,
    /// Relocatable object.
    Relocatable,
    /// Fixed-address executable: no ASLR for its code.
    No,
}

/// RELRO protection of the GOT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Relro {
    /// `PT_GNU_RELRO` and immediate binding: the whole GOT is read-only.
    Full,
    /// `PT_GNU_RELRO` with lazy binding: `.got.plt` stays writable.
    Partial,
    /// No `PT_GNU_RELRO`.
    None,
    /// Dart AOT code (MobSF: not applicable).
    NotApplicable,
}

/// Hardening properties of one library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardening {
    /// `PT_GNU_STACK` present and not executable (MobSF/LIEF `has_nx`).
    pub nx: bool,
    /// Position independence.
    pub pie: PieKind,
    /// Stack protector symbols present (assumed for Dart code).
    pub stack_canary: bool,
    /// RELRO.
    pub relro: Relro,
    /// `DT_RPATH`.
    pub rpath: Option<String>,
    /// `DT_RUNPATH`.
    pub runpath: Option<String>,
    /// `*_chk` (fortified) functions, sorted.
    pub fortified: Vec<String>,
    /// No named `.symtab` symbols.
    pub stripped: bool,
    /// `.debug_*` sections present.
    pub debug_info: bool,
    /// Text relocations (`DT_TEXTREL` or `DF_TEXTREL`).
    pub text_relocations: bool,
    /// Dart AOT snapshot (Flutter `libapp.so`, `libflutter.so`).
    pub dart: bool,
    /// Smallest `PT_LOAD` alignment: the largest page size the library supports.
    pub load_alignment: Option<u64>,
    /// First `.comment` string (compiler and NDK version).
    pub compiler: Option<String>,
}

impl Hardening {
    /// Computes the hardening properties of a parsed library.
    pub fn of(elf: &Elf) -> Self {
        let dart = DART_SYMBOLS.iter().any(|symbol| elf.has_symbol(symbol));
        let mut fortified: Vec<String> = elf
            .dynamic_symbols
            .iter()
            .map(|symbol| symbol.name.as_str())
            .chain(elf.static_symbols.iter().map(String::as_str))
            .filter(|name| name.ends_with("_chk"))
            .map(str::to_owned)
            .collect();
        fortified.sort();
        fortified.dedup();
        let flags = elf.dynamic_value(DT_FLAGS).unwrap_or(0);
        Self {
            nx: elf
                .segment(PT_GNU_STACK)
                .is_some_and(|stack| stack.flags & PF_X == 0),
            pie: match elf.kind {
                ElfKind::Shared if elf.dynamic_value(DT_DEBUG).is_some() => PieKind::Pie,
                ElfKind::Shared => PieKind::Dso,
                ElfKind::Relocatable => PieKind::Relocatable,
                _ => PieKind::No,
            },
            stack_canary: dart || CANARY_SYMBOLS.iter().any(|symbol| elf.has_symbol(symbol)),
            relro: relro(elf, dart),
            rpath: elf.rpath.clone(),
            runpath: elf.runpath.clone(),
            fortified,
            stripped: !elf.static_symbols.iter().any(|name| !name.is_empty()),
            debug_info: elf.sections.iter().any(|section| {
                section.name.starts_with(".debug_") || section.name.starts_with(".zdebug_")
            }),
            text_relocations: elf.dynamic_value(DT_TEXTREL).is_some() || flags & DF_TEXTREL != 0,
            dart,
            load_alignment: elf
                .segments
                .iter()
                .filter(|segment| segment.kind == PT_LOAD)
                .map(|segment| segment.align)
                .min(),
            // The compiler line (`... clang version 17.0.2`, `GCC: ...`) says more than the
            // linker line that often comes first.
            compiler: elf
                .comments
                .iter()
                .find(|comment| comment.contains("clang version") || comment.starts_with("GCC:"))
                .or_else(|| elf.comments.first())
                .cloned(),
        }
    }
}

/// MobSF counts `DF_BIND_NOW` and `DF_1_NOW`; `DT_BIND_NOW` means the same and is counted too.
fn relro(elf: &Elf, dart: bool) -> Relro {
    if dart {
        return Relro::NotApplicable;
    }
    if elf.segment(PT_GNU_RELRO).is_none() {
        return Relro::None;
    }
    let bind_now = elf
        .dynamic_value(DT_FLAGS)
        .is_some_and(|flags| flags & DF_BIND_NOW != 0)
        || elf
            .dynamic_value(DT_FLAGS_1)
            .is_some_and(|flags| flags & DF_1_NOW != 0)
        || elf.dynamic_value(DT_BIND_NOW).is_some();
    if bind_now {
        Relro::Full
    } else {
        Relro::Partial
    }
}

/// One `.so` file in the APK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLibrary {
    /// Entry name (`lib/arm64-v8a/libapp.so`).
    pub path: String,
    /// ABI directory when under `lib/<abi>/`.
    pub abi: Option<String>,
    /// Stored uncompressed (Android can map it directly from the APK).
    pub stored: bool,
    /// File offset of the entry's data in the APK.
    pub data_offset: Option<u64>,
    /// Uncompressed size.
    pub size: u64,
    /// The parsed file, or why it is not ELF.
    pub elf: Result<Elf, ElfError>,
    /// Hardening, when parsed.
    pub hardening: Option<Hardening>,
}

impl NativeLibrary {
    /// 64-bit code for a 64-bit Android ABI: the libraries Google Play's 16 KB page-size
    /// requirement applies to.
    pub fn is_64_bit(&self) -> bool {
        self.elf.as_ref().is_ok_and(|elf| elf.class == Class::Elf64)
    }
}

/// Reads and analyses every `.so` entry, wherever it is (MobSF also scans every `*.so`).
pub fn read_native_libraries<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Vec<NativeLibrary> {
    let candidates: Vec<(usize, String, bool, Option<u64>, u64)> = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory && entry.name.ends_with(".so"))
        .map(|entry| {
            (
                entry.index,
                entry.name.clone(),
                entry.method == 0,
                entry.data_offset(),
                entry.uncompressed_size,
            )
        })
        .collect();
    candidates
        .into_iter()
        .map(|(index, path, stored, data_offset, size)| {
            let abi = abi_of(&path);
            read_library(archive, index, path, abi, stored, data_offset, size)
        })
        .collect()
}

/// Reads and analyses one library entry.
pub(crate) fn read_library<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    path: String,
    abi: Option<String>,
    stored: bool,
    data_offset: Option<u64>,
    size: u64,
) -> NativeLibrary {
    let elf = archive
        .read(index)
        .map_err(|_| ElfError::Truncated)
        .and_then(|bytes| Elf::parse(&bytes));
    let hardening = elf.as_ref().ok().map(Hardening::of);
    NativeLibrary {
        path,
        abi,
        stored,
        data_offset,
        size,
        elf,
        hardening,
    }
}

fn abi_of(path: &str) -> Option<String> {
    let rest = path.strip_prefix("lib/")?;
    let (abi, file) = rest.split_once('/')?;
    (!file.contains('/')).then(|| abi.to_owned())
}
