//! Hardening properties of an image, as MobSF's `MachOChecksec` judges them (LIEF-based), plus
//! the fortified-function count (msec origin). Several are heuristics on imported symbols, as
//! in MobSF: a stack protector is assumed when `___stack_chk_fail` and `___stack_chk_guard` are
//! both imported, ARC when an ARC runtime function is. MobSF looks for `_objc_release` and
//! `_swift_release` only; today's clang calls register-specific variants
//! (`_objc_release_x20`, `_swift_release_x24`) and ARC-only entry points (`_objc_storeStrong`,
//! `_objc_claimAutoreleasedReturnValue`), which msec also counts. Code that never retains an
//! object imports none of them even when compiled with ARC.

use super::MachO;

/// Imported functions that mark a stack-protected image (MobSF requires both).
const STACK_CHECK: [&str; 2] = ["___stack_chk_fail", "___stack_chk_guard"];
/// Imported functions that mark automatic reference counting (Objective-C, Swift): MobSF's two,
/// and the ARC-only entry points clang emits.
const ARC_FUNCTIONS: [&str; 7] = [
    "_objc_release",
    "_swift_release",
    "_objc_storeStrong",
    "_objc_claimAutoreleasedReturnValue",
    "_objc_retainAutoreleasedReturnValue",
    "_objc_autoreleaseReturnValue",
    "_objc_retainAutoreleaseReturnValue",
];
/// Prefixes of register-specific ARC calls (`_objc_release_x19`, `_swift_release_x24`): clang
/// and swiftc emit these instead of the plain functions.
const ARC_REGISTER_PREFIXES: [&str; 3] = ["_objc_release_x", "_swift_release_x", "_swift_retain_x"];

/// What an image's header, load commands and imports say about its hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// `MH_PIE` (executables only; libraries are always position-independent).
    pub pie: Option<bool>,
    /// The stack is not executable (no `MH_ALLOW_STACK_EXECUTION`).
    pub nx_stack: bool,
    /// `MH_NO_HEAP_EXECUTION`.
    pub nx_heap: bool,
    /// Stack protector (heuristic: both stack-check symbols imported).
    pub stack_canary: bool,
    /// Automatic reference counting (heuristic: an ARC runtime function imported).
    pub arc: bool,
    /// Links the Objective-C runtime.
    pub objective_c: bool,
    /// Contains Swift (Swift runtime imports or `libswiftCore`).
    pub swift: bool,
    /// `__*_chk` fortified functions imported.
    pub fortified_functions: usize,
    /// `LC_ENCRYPTION_INFO(_64)`'s `cryptid` is set; `None` without the command.
    pub encrypted: Option<bool>,
    /// `LC_CODE_SIGNATURE` with data.
    pub code_signature: bool,
    /// `LC_RPATH` entries.
    pub rpaths: usize,
    /// No debugging symbols (`N_STAB`) in the symbol table.
    pub stripped: bool,
}

impl Hardening {
    /// The properties of `image`.
    pub fn of(image: &MachO) -> Self {
        let imports = image
            .symbols
            .as_ref()
            .map(|symbols| symbols.imports.as_slice())
            .unwrap_or_default();
        let links = |fragment: &str| {
            image
                .dylibs
                .iter()
                .any(|dylib| dylib.name.contains(fragment))
        };
        Self {
            pie: image.header.is_executable().then(|| image.header.is_pie()),
            nx_stack: !image.header.allows_stack_execution(),
            nx_heap: image.header.no_heap_execution(),
            stack_canary: STACK_CHECK.iter().all(|symbol| image.imports(symbol)),
            arc: ARC_FUNCTIONS.iter().any(|symbol| image.imports(symbol))
                || imports.iter().any(|name| {
                    ARC_REGISTER_PREFIXES
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
                }),
            objective_c: links("libobjc") || imports.iter().any(|name| name.starts_with("_objc_")),
            swift: links("libswiftCore") || imports.iter().any(|name| name.starts_with("_swift_")),
            fortified_functions: imports
                .iter()
                .filter(|name| name.starts_with("___") && name.ends_with("_chk"))
                .filter(|name| !STACK_CHECK.contains(&name.as_str()))
                .count(),
            encrypted: image.encryption.map(|encryption| encryption.encrypted()),
            code_signature: image
                .code_signature
                .is_some_and(|signature| signature.size > 0),
            rpaths: image.rpaths.len(),
            stripped: image
                .symbols
                .as_ref()
                .is_none_or(|symbols| symbols.debug == 0),
        }
    }
}
