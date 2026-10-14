//! Native library checks (MobSF `elf.py::ELFChecksec` severities), plus Android loading and
//! Google Play requirements MobSF does not check.

use super::{Origin, Severity};
use crate::android::native::{NativeLibrary, PieKind, Relro};

/// Google Play: 64-bit native code must support 16 KB memory pages (apps targeting Android 15+
/// since November 2025): `PT_LOAD` alignment and ZIP alignment of uncompressed libraries.
const PAGE_16_KB: u64 = 16 * 1024;
/// Uncompressed 32-bit libraries must at least be 4 KB aligned for Android to map them.
const PAGE_4_KB: u64 = 4 * 1024;

/// A native library rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeRule {
    /// No non-executable stack marking (MobSF high).
    NxMissing,
    /// Not position-independent (MobSF high).
    PieMissing,
    /// No stack canary (MobSF high).
    StackCanaryMissing,
    /// No RELRO (MobSF high).
    RelroMissing,
    /// Partial RELRO (MobSF warning).
    RelroPartial,
    /// `DT_RPATH` set (MobSF high).
    Rpath,
    /// `DT_RUNPATH` set (MobSF high).
    Runpath,
    /// No fortified functions (MobSF warning).
    FortifyMissing,
    /// Symbol table not stripped (MobSF warning).
    SymbolsNotStripped,
    /// msec: text relocations; Android 6.0+ refuses to load them for apps targeting API 23+.
    TextRelocations,
    /// msec: DWARF debug sections shipped.
    DebugInfo,
    /// msec: 64-bit library aligned for 4 KB pages only.
    NotAlignedFor16KbPages,
    /// msec: uncompressed library not page-aligned inside the APK.
    ZipMisaligned,
}

impl NativeRule {
    /// Engine key.
    pub fn key(self) -> &'static str {
        match self {
            Self::NxMissing => "elf_nx_missing",
            Self::PieMissing => "elf_pie_missing",
            Self::StackCanaryMissing => "elf_stack_canary_missing",
            Self::RelroMissing => "elf_relro_missing",
            Self::RelroPartial => "elf_relro_partial",
            Self::Rpath => "elf_rpath",
            Self::Runpath => "elf_runpath",
            Self::FortifyMissing => "elf_fortify_missing",
            Self::SymbolsNotStripped => "elf_symbols_not_stripped",
            Self::TextRelocations => "msec_elf_text_relocations",
            Self::DebugInfo => "msec_elf_debug_info",
            Self::NotAlignedFor16KbPages => "msec_elf_not_16kb_aligned",
            Self::ZipMisaligned => "msec_elf_zip_misaligned",
        }
    }

    /// MobSF's severity for its checks; msec's own on the same scale.
    pub fn severity(self) -> Severity {
        match self {
            Self::NxMissing
            | Self::PieMissing
            | Self::StackCanaryMissing
            | Self::RelroMissing
            | Self::Rpath
            | Self::Runpath
            | Self::TextRelocations => Severity::High,
            _ => Severity::Warning,
        }
    }

    /// Where the rule comes from.
    pub fn origin(self) -> Origin {
        match self {
            Self::TextRelocations
            | Self::DebugInfo
            | Self::NotAlignedFor16KbPages
            | Self::ZipMisaligned => Origin::Msec,
            _ => Origin::MobSf,
        }
    }
}

/// One finding about one library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFinding {
    /// The rule.
    pub rule: NativeRule,
    /// The library (`lib/arm64-v8a/libfoo.so`).
    pub library: String,
    /// What triggered it.
    pub detail: Option<String>,
}

/// Checks every parsed library.
pub fn analyse_native(libraries: &[NativeLibrary]) -> Vec<NativeFinding> {
    let mut findings = Vec::new();
    for library in libraries {
        let Some(hardening) = &library.hardening else {
            continue;
        };
        let mut add = |rule: NativeRule, detail: Option<String>| {
            findings.push(NativeFinding {
                rule,
                library: library.path.clone(),
                detail,
            });
        };
        if !hardening.nx {
            add(NativeRule::NxMissing, None);
        }
        if hardening.pie == PieKind::No {
            add(NativeRule::PieMissing, None);
        }
        if !hardening.stack_canary {
            add(NativeRule::StackCanaryMissing, None);
        }
        match hardening.relro {
            Relro::None => add(NativeRule::RelroMissing, None),
            Relro::Partial => add(NativeRule::RelroPartial, None),
            Relro::Full | Relro::NotApplicable => {}
        }
        if let Some(path) = &hardening.rpath {
            add(NativeRule::Rpath, Some(path.clone()));
        }
        if let Some(path) = &hardening.runpath {
            add(NativeRule::Runpath, Some(path.clone()));
        }
        if hardening.fortified.is_empty() && !hardening.dart {
            add(NativeRule::FortifyMissing, None);
        }
        if !hardening.stripped {
            add(NativeRule::SymbolsNotStripped, None);
        }
        if hardening.text_relocations {
            add(NativeRule::TextRelocations, None);
        }
        if hardening.debug_info {
            add(NativeRule::DebugInfo, None);
        }
        if library.is_64_bit()
            && hardening
                .load_alignment
                .is_some_and(|align| align < PAGE_16_KB)
        {
            add(
                NativeRule::NotAlignedFor16KbPages,
                hardening
                    .load_alignment
                    .map(|align| format!("{} KB pages", align / 1024)),
            );
        }
        let required = if library.is_64_bit() {
            PAGE_16_KB
        } else {
            PAGE_4_KB
        };
        if library.stored
            && library.abi.is_some()
            && library
                .data_offset
                .is_some_and(|offset| offset % required != 0)
        {
            add(
                NativeRule::ZipMisaligned,
                library
                    .data_offset
                    .map(|offset| format!("offset {offset} is not {} KB aligned", required / 1024)),
            );
        }
    }
    findings
}
