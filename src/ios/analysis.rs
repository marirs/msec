//! Security checks on an app bundle's executables: MobSF's Mach-O checksec findings (PIE,
//! executable stack, stack protector, ARC, debug symbols), its IPA binary rules on imported
//! functions, and checks MobSF does not make ([`Origin::Msec`]): the code signature (missing,
//! or not matching what it seals), run-path search paths that leave the bundle, and the
//! `get-task-allow` entitlement.
//!
//! The stack-protector and ARC checks are heuristics on imports ([`crate::macho::Hardening`]).
//! A binary with Swift code is not held to the stack protector: Swift's own code does not use
//! it, and its runtime interop imports C functions, so a missing import there does not show
//! that C code lacks protection. Run-path search paths in the system's read-only volumes
//! (`/usr/lib/swift`, which swiftc adds) are not "outside the bundle".

use super::{AppBundle, BundleBinary, SignatureKind};
use crate::android::analysis::{Origin, Severity};
use crate::macho::{Hardening, MachO};
use crate::plist::Value;

/// Functions without a bounds argument: MobSF's insecure-API list keeps only these (it also
/// lists `memcpy`, `strlen`, `malloc` and `printf`, which every C program imports).
const UNBOUNDED_FUNCTIONS: [&str; 10] = [
    "_gets",
    "_strcpy",
    "_strcat",
    "_sprintf",
    "_vsprintf",
    "_wcscpy",
    "_wcscat",
    "_swprintf",
    "_vswprintf",
    "_stpcpy",
];
/// Weak hash functions from CommonCrypto.
const WEAK_HASHES: [&str; 6] = [
    "_CC_MD2",
    "_CC_MD4",
    "_CC_MD5",
    "_CC_SHA1",
    "_CC_MD5_Init",
    "_CC_SHA1_Init",
];
/// C library random numbers, predictable by design.
const INSECURE_RANDOM: [&str; 4] = ["_rand", "_srand", "_random", "_srandom"];

/// A check on an executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BinaryRule {
    /// An executable not built position-independent (MobSF `pie`).
    NotPie,
    /// The stack is executable (MobSF `nx`).
    ExecutableStack,
    /// No stack protector (MobSF `stack_canary`; heuristic on imports).
    NoStackCanary,
    /// Objective-C code without automatic reference counting (MobSF `arc`; heuristic).
    NoArc,
    /// The debug map is still in the symbol table (MobSF `symbol`).
    DebugSymbols,
    /// No code signature at all (msec).
    Unsigned,
    /// The code signature does not match the code or what it seals (msec).
    SignatureMismatch,
    /// A run-path search path outside the bundle (msec): libraries can be loaded from there.
    RpathOutsideBundle,
    /// Functions without bounds checking are imported (MobSF IPA rule, narrowed).
    UnboundedFunctions,
    /// Weak hash functions are imported (MobSF IPA rule).
    WeakHashes,
    /// C library random numbers are imported (MobSF IPA rule).
    InsecureRandom,
    /// The main executable's entitlements allow debugging (`get-task-allow`): a development
    /// build (msec).
    GetTaskAllow,
}

impl BinaryRule {
    /// Engine key.
    pub fn key(self) -> &'static str {
        match self {
            Self::NotPie => "msec_macho_not_pie",
            Self::ExecutableStack => "msec_macho_executable_stack",
            Self::NoStackCanary => "msec_macho_no_stack_canary",
            Self::NoArc => "msec_macho_no_arc",
            Self::DebugSymbols => "msec_macho_debug_symbols",
            Self::Unsigned => "msec_macho_unsigned",
            Self::SignatureMismatch => "msec_macho_signature_mismatch",
            Self::RpathOutsideBundle => "msec_macho_rpath_outside_bundle",
            Self::UnboundedFunctions => "msec_macho_unbounded_functions",
            Self::WeakHashes => "msec_macho_weak_hashes",
            Self::InsecureRandom => "msec_macho_insecure_random",
            Self::GetTaskAllow => "msec_ios_get_task_allow",
        }
    }

    /// Severity on MobSF's scale.
    pub fn severity(self) -> Severity {
        match self {
            Self::NotPie
            | Self::ExecutableStack
            | Self::NoStackCanary
            | Self::NoArc
            | Self::Unsigned
            | Self::SignatureMismatch
            | Self::GetTaskAllow => Severity::High,
            Self::UnboundedFunctions | Self::WeakHashes | Self::RpathOutsideBundle => {
                Severity::Warning
            }
            Self::DebugSymbols | Self::InsecureRandom => Severity::Info,
        }
    }

    /// Where the rule comes from.
    pub fn origin(self) -> Origin {
        match self {
            Self::Unsigned
            | Self::SignatureMismatch
            | Self::RpathOutsideBundle
            | Self::GetTaskAllow => Origin::Msec,
            _ => Origin::MobSf,
        }
    }
}

/// One finding about one executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFinding {
    /// The rule.
    pub rule: BinaryRule,
    /// The executable's path in the archive.
    pub binary: String,
    /// The architecture, when the finding concerns one slice of several.
    pub architecture: Option<String>,
    /// What triggered it.
    pub detail: String,
}

/// Every check on every executable of the bundle that was read.
pub fn analyse_binaries(app: &AppBundle) -> Vec<BinaryFinding> {
    let mut findings: Vec<BinaryFinding> = app.binaries.iter().flat_map(analyse_binary).collect();
    if let Some(main) = app.binaries.first()
        && let Some(Ok(entitlements)) = main.entitlements()
        && entitlements.root.get("get-task-allow") == Some(&Value::Boolean(true))
    {
        findings.push(BinaryFinding {
            rule: BinaryRule::GetTaskAllow,
            binary: main.path.clone(),
            architecture: None,
            detail: "get-task-allow is true: the app can be debugged (a development build)"
                .to_owned(),
        });
    }
    findings.sort_by(|left, right| (left.rule, &left.binary).cmp(&(right.rule, &right.binary)));
    findings.dedup();
    findings
}

/// The checks on one executable (every slice), the entitlement check aside.
pub fn analyse_binary(binary: &BundleBinary) -> Vec<BinaryFinding> {
    let mut findings = Vec::new();
    let several = binary.images().count() > 1;
    for (index, image) in binary.images().enumerate() {
        let architecture = several.then(|| {
            binary.signatures.get(index).map_or_else(
                || format!("slice {index}"),
                |check| check.architecture.clone(),
            )
        });
        let mut push = |rule: BinaryRule, detail: String| {
            findings.push(BinaryFinding {
                rule,
                binary: binary.path.clone(),
                architecture: architecture.clone(),
                detail,
            });
        };
        image_checks(image, &mut push);
    }
    signature_checks(binary, &mut findings);
    findings
}

fn image_checks(image: &MachO, push: &mut impl FnMut(BinaryRule, String)) {
    let hardening = Hardening::of(image);
    if hardening.pie == Some(false) {
        push(
            BinaryRule::NotPie,
            "MH_PIE is not set: the executable loads at a fixed address".to_owned(),
        );
    }
    if !hardening.nx_stack {
        push(
            BinaryRule::ExecutableStack,
            "MH_ALLOW_STACK_EXECUTION is set: the stack is executable".to_owned(),
        );
    }
    if !hardening.stack_canary && !hardening.swift {
        push(
            BinaryRule::NoStackCanary,
            "___stack_chk_fail and ___stack_chk_guard are not both imported (heuristic): no \
             stack protector"
                .to_owned(),
        );
    }
    if hardening.objective_c && !hardening.arc {
        push(
            BinaryRule::NoArc,
            "Objective-C without ARC runtime calls (heuristic): manual reference counting, or \
             code that never retains an object"
                .to_owned(),
        );
    }
    if !hardening.stripped {
        let entries = image.symbols.as_ref().map_or(0, |symbols| symbols.debug);
        push(
            BinaryRule::DebugSymbols,
            format!("{entries} debug entries in the symbol table: not stripped"),
        );
    }
    for rpath in &image.rpaths {
        let inside = ["@executable_path", "@loader_path", "/usr/lib/", "/System/"]
            .iter()
            .any(|prefix| rpath.starts_with(prefix));
        if !inside {
            push(
                BinaryRule::RpathOutsideBundle,
                format!("LC_RPATH {rpath}: libraries are searched outside the bundle"),
            );
        }
    }
    for (rule, names) in [
        (BinaryRule::UnboundedFunctions, &UNBOUNDED_FUNCTIONS[..]),
        (BinaryRule::WeakHashes, &WEAK_HASHES[..]),
        (BinaryRule::InsecureRandom, &INSECURE_RANDOM[..]),
    ] {
        let found: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| image.imports(name))
            .map(|name| name.trim_start_matches('_'))
            .collect();
        if !found.is_empty() {
            push(rule, format!("imports {}", found.join(", ")));
        }
    }
}

fn signature_checks(binary: &BundleBinary, findings: &mut Vec<BinaryFinding>) {
    let several = binary.signatures.len() > 1;
    for check in &binary.signatures {
        let architecture = several.then(|| check.architecture.clone());
        let detail = match &check.kind {
            SignatureKind::Unsigned => Some((
                BinaryRule::Unsigned,
                "no LC_CODE_SIGNATURE: iOS does not run unsigned code".to_owned(),
            )),
            SignatureKind::Unreadable(why) => Some((
                BinaryRule::SignatureMismatch,
                format!("the code signature cannot be read: {why}"),
            )),
            SignatureKind::AdHoc | SignatureKind::Certificate => {
                mismatch(check).map(|why| (BinaryRule::SignatureMismatch, why))
            }
        };
        if let Some((rule, detail)) = detail {
            findings.push(BinaryFinding {
                rule,
                binary: binary.path.clone(),
                architecture,
                detail,
            });
        }
    }
}

/// What does not match, in words; `None` when everything checked matches.
fn mismatch(check: &super::SignatureCheck) -> Option<String> {
    let mut parts = Vec::new();
    if check.pages == Some(false) {
        let pages = check
            .mismatched_pages
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("code pages {pages} changed after signing"));
    }
    if check.info_plist == Some(false) {
        parts.push("Info.plist changed after signing".to_owned());
    }
    if check.resources == Some(false) {
        parts.push("_CodeSignature/CodeResources changed after signing".to_owned());
    }
    if check.embedded_blobs == Some(false) {
        parts.push("the entitlements or requirements do not match the signature".to_owned());
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}
