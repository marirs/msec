//! Security checks on an app bundle's executables: MobSF's Mach-O checksec findings (PIE,
//! executable stack, stack protector, ARC, debug symbols), its IPA binary rules on imported
//! functions, and checks MobSF does not make ([`Origin::Msec`]): the code signature (missing,
//! or not matching what it seals), run-path search paths that leave the bundle, and the
//! `get-task-allow` entitlement.
//!
//! The crypto, storage, WebView and logging checks rest on what an executable imports (a
//! function, a constant, a class) or, for WebKit preferences set by key-value coding, on a C
//! string naming the key ([`BinaryEvidence`]). Either shows the code refers to the API, not
//! that it runs or what data it handles: none of these findings is a proven vulnerability.
//! Arguments are not read (that needs disassembly), so CommonCrypto's cipher and mode
//! constants, and `Data.WritingOptions.noFileProtection`, are not seen.
//!
//! The stack-protector and ARC checks are heuristics on imports ([`crate::macho::Hardening`]).
//! A binary with Swift code is not held to the stack protector: Swift's own code does not use
//! it, and its runtime interop imports C functions, so a missing import there does not show
//! that C code lacks protection. Run-path search paths in the system's read-only volumes
//! (`/usr/lib/swift`, which swiftc adds) are not "outside the bundle".

use super::profile::ProfileKind;
use super::{AppBundle, BundleBinary, SignatureKind};
use crate::android::analysis::{Origin, Severity};
use crate::macho::der_entitlements::same_entitlements;
use crate::macho::signer::Signer;
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
/// CryptoKit's `Insecure` namespace (MD5, SHA-1 and their digests): Swift imports its type
/// metadata and conformances, since the hash functions themselves are inlined generics
/// (checked with `nm -u` on swiftc output, `tests/fixtures/ios/security`).
const CRYPTOKIT_INSECURE_PREFIX: &str = "_$s9CryptoKit8InsecureO";
/// C library random numbers, predictable by design.
const INSECURE_RANDOM: [&str; 4] = ["_rand", "_srand", "_random", "_srandom"];
/// `(symbol, name)` of logging functions, as MASTG-TEST-0297 lists them: `NSLog` and `NSLogv`
/// write to the unified system log; Swift's `print` and `debugPrint` and C's `printf` write to
/// standard output. `os_log` and `Logger`, which redact dynamic values unless marked public,
/// are not listed.
const LOGGING_FUNCTIONS: [(&str, &str); 5] = [
    ("_NSLog", "NSLog"),
    ("_NSLogv", "NSLogv"),
    ("_printf", "printf"),
    (
        "_$ss5print_9separator10terminatoryypd_S2StF",
        "print (Swift)",
    ),
    (
        "_$ss10debugPrint_9separator10terminatoryypd_S2StF",
        "debugPrint (Swift)",
    ),
];
/// `(symbol, name)` of the file protection class that leaves a file readable while the device
/// is locked (MASTG-TEST-0300). Swift's `FileProtectionType.none` and `URLFileProtection.none`
/// import the same constants.
const FILE_PROTECTION_NONE: [(&str, &str); 2] = [
    ("_NSFileProtectionNone", "NSFileProtectionNone"),
    ("_NSURLFileProtectionNone", "NSURLFileProtectionNone"),
];
/// `(symbol, name)` of the keychain accessibility values that keep an item readable while the
/// device is locked (deprecated since iOS 12).
const KEYCHAIN_ACCESSIBLE_ALWAYS: [(&str, &str); 2] = [
    ("_kSecAttrAccessibleAlways", "kSecAttrAccessibleAlways"),
    (
        "_kSecAttrAccessibleAlwaysThisDeviceOnly",
        "kSecAttrAccessibleAlwaysThisDeviceOnly",
    ),
];
/// `(symbol, name)` of the deprecated `UIWebView` class (MASTG-TEST-0331; App Store Connect
/// refuses it, ITMS-90809): referenced to create, or to subclass, one.
const UIWEBVIEW_CLASS: [(&str, &str); 2] = [
    ("_OBJC_CLASS_$_UIWebView", "UIWebView"),
    ("_OBJC_METACLASS_$_UIWebView", "UIWebView (subclassed)"),
];
/// The WebKit preferences that relax the file origin rules (MASTG-TEST-0335). They are not
/// public API: apps set them by key-value coding, so the key is a string in the executable.
pub const WEBVIEW_FILE_ORIGIN_KEYS: [&str; 2] = [
    "allowFileAccessFromFileURLs",
    "allowUniversalAccessFromFileURLs",
];

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
    /// Logging functions are imported (msec).
    LoggingApi,
    /// The "none" file protection class is imported: files readable while the device is
    /// locked (msec).
    FileProtectionNone,
    /// A keychain accessibility value that keeps items readable while the device is locked is
    /// imported (msec).
    KeychainAccessibleAlways,
    /// The deprecated `UIWebView` class is referenced (msec).
    UiWebView,
    /// A C string names a WebKit preference that relaxes the file origin rules (msec).
    WebViewFileOriginRelaxed,
    /// The main executable's entitlements allow debugging (`get-task-allow`): a development
    /// build (msec).
    GetTaskAllow,
    /// The CMS signature does not verify over the CodeDirectory: the signature was changed, or
    /// signs other code (msec).
    CmsSignatureInvalid,
    /// The signing certificate's chain does not end at one of Apple's root certificates, or a
    /// link does not verify: stock iOS does not run it (msec).
    SignerNotApple,
    /// The CodeDirectory names a team other than the signing certificate's; iOS refuses such
    /// code at install (msec; codesign --verify accepts it).
    TeamMismatch,
    /// The DER entitlements, which iOS 15 and later read, say something other than the XML
    /// ones, or cannot be read (msec).
    EntitlementsDiffer,
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
            Self::LoggingApi => "msec_macho_logging_api",
            Self::FileProtectionNone => "msec_macho_file_protection_none",
            Self::KeychainAccessibleAlways => "msec_macho_keychain_accessible_always",
            Self::UiWebView => "msec_macho_uiwebview",
            Self::WebViewFileOriginRelaxed => "msec_macho_webview_file_origin_relaxed",
            Self::GetTaskAllow => "msec_ios_get_task_allow",
            Self::CmsSignatureInvalid => "msec_macho_cms_signature_invalid",
            Self::SignerNotApple => "msec_macho_signer_not_apple",
            Self::TeamMismatch => "msec_macho_team_mismatch",
            Self::EntitlementsDiffer => "msec_macho_entitlements_differ",
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
            | Self::GetTaskAllow
            | Self::CmsSignatureInvalid
            | Self::SignerNotApple
            | Self::TeamMismatch
            | Self::EntitlementsDiffer => Severity::High,
            Self::UnboundedFunctions
            | Self::WeakHashes
            | Self::RpathOutsideBundle
            | Self::FileProtectionNone
            | Self::KeychainAccessibleAlways
            | Self::UiWebView
            | Self::WebViewFileOriginRelaxed => Severity::Warning,
            Self::DebugSymbols | Self::InsecureRandom | Self::LoggingApi => Severity::Info,
        }
    }

    /// Where the rule comes from.
    pub fn origin(self) -> Origin {
        match self {
            Self::Unsigned
            | Self::SignatureMismatch
            | Self::RpathOutsideBundle
            | Self::GetTaskAllow
            | Self::CmsSignatureInvalid
            | Self::SignerNotApple
            | Self::TeamMismatch
            | Self::EntitlementsDiffer
            | Self::LoggingApi
            | Self::FileProtectionNone
            | Self::KeychainAccessibleAlways
            | Self::UiWebView
            | Self::WebViewFileOriginRelaxed => Origin::Msec,
            _ => Origin::MobSf,
        }
    }

    /// What a code finding of this rule rests on; `None` for checks that are not about the
    /// code's use of an API (hardening flags, signatures, entitlements).
    pub fn evidence(self) -> Option<BinaryEvidence> {
        match self {
            Self::UnboundedFunctions
            | Self::WeakHashes
            | Self::InsecureRandom
            | Self::LoggingApi
            | Self::FileProtectionNone
            | Self::KeychainAccessibleAlways
            | Self::UiWebView => Some(BinaryEvidence::Import),
            Self::WebViewFileOriginRelaxed => Some(BinaryEvidence::String),
            _ => None,
        }
    }

    /// The rules that read the symbol table's imports: an image whose symbol table was not
    /// read leaves them incomplete ([`super::coverage`]), and the hardening heuristics among
    /// them report nothing for it rather than a missing protection.
    pub const READ_IMPORTS: [Self; 9] = [
        Self::NoStackCanary,
        Self::NoArc,
        Self::UnboundedFunctions,
        Self::WeakHashes,
        Self::InsecureRandom,
        Self::LoggingApi,
        Self::FileProtectionNone,
        Self::KeychainAccessibleAlways,
        Self::UiWebView,
    ];
}

/// What a code finding rests on. Neither is a proven vulnerability: whether the code runs, and
/// with what data, is not established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BinaryEvidence {
    /// The executable imports the symbol (a function, a constant, a class).
    Import,
    /// A C string in the executable names the setting.
    String,
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
    // MobSF reports get-task-allow whatever the build; msec does too, and says what the
    // distribution method makes of it, which callers judge by (`super::distribution`): a
    // development build is expected to have it.
    if let Some(main) = app.binaries.first()
        && debuggable(main)
    {
        let detail = match super::distribution::of(app) {
            super::distribution::Distribution::Established { kind, .. } => match kind {
                ProfileKind::Development => "get-task-allow is true: the app can be debugged, \
                                             as a development build (development profile) is \
                                             meant to be"
                    .to_owned(),
                other => format!(
                    "get-task-allow is true: the app can be debugged, in a build whose \
                     profile is for {} distribution",
                    other.label()
                ),
            },
            super::distribution::Distribution::Unknown { reason, .. } => format!(
                "get-task-allow is true: the app can be debugged; whether it is a development \
                 build is not established: {reason}"
            ),
        };
        findings.push(BinaryFinding {
            rule: BinaryRule::GetTaskAllow,
            binary: main.path.clone(),
            architecture: None,
            detail,
        });
    }
    findings.sort_by(|left, right| (left.rule, &left.binary).cmp(&(right.rule, &right.binary)));
    findings.dedup();
    findings
}

/// The executable's entitlements set `get-task-allow`. Either encoding counts: iOS 15 and
/// later read the DER entitlements, earlier releases the XML ones.
pub(super) fn debuggable(binary: &BundleBinary) -> bool {
    let xml = matches!(
        binary.entitlements(),
        Some(Ok(entitlements)) if entitlements.root.get("get-task-allow") == Some(&Value::Boolean(true))
    );
    let der = binary.images().any(|image| {
        matches!(&image.signature, Some(Ok(signature)) if matches!(
            signature.der_entitlements_decoded(),
            Some(Ok(der)) if der.dictionary.get("get-task-allow") == Some(&Value::Boolean(true))
        ))
    });
    xml || der
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
        entitlement_checks(image, &mut push);
    }
    if !binary.webview_file_origin_keys.is_empty() {
        findings.push(BinaryFinding {
            rule: BinaryRule::WebViewFileOriginRelaxed,
            binary: binary.path.clone(),
            architecture: None,
            detail: format!(
                "names the WebKit preference {} (set by key-value coding): JavaScript in a \
                 file: page may read other files, or any origin; the value set, and which web \
                 view it configures, are not established",
                binary.webview_file_origin_keys.join(", ")
            ),
        });
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
    // Without a symbol table every import check reads nothing: the import-based heuristics
    // would report missing protections that were never looked for. The image is reported as
    // not read ([`super::coverage`]) instead.
    // msec differs: MobSF reports no stack canary and no ARC for such an image.
    let imports_read = image.symbols.is_some();
    if imports_read && !hardening.stack_canary && !hardening.swift {
        push(
            BinaryRule::NoStackCanary,
            "___stack_chk_fail and ___stack_chk_guard are not both imported (heuristic): no \
             stack protector"
                .to_owned(),
        );
    }
    if imports_read && hardening.objective_c && !hardening.arc {
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
        let mut found: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| image.imports(name))
            .map(|name| name.trim_start_matches('_'))
            .collect();
        if rule == BinaryRule::WeakHashes {
            found.extend(insecure_cryptokit_hashes(image));
        }
        if !found.is_empty() {
            push(rule, format!("imports {}", found.join(", ")));
        }
    }
    named_import_checks(image, push);
}

/// The crypto, storage, WebView and logging checks on imports, each naming what it found.
fn named_import_checks(image: &MachO, push: &mut impl FnMut(BinaryRule, String)) {
    let named = |list: &[(&str, &'static str)]| -> Vec<&'static str> {
        list.iter()
            .filter(|(symbol, _)| image.imports(symbol))
            .map(|(_, name)| *name)
            .collect()
    };
    let logging = named(&LOGGING_FUNCTIONS);
    if !logging.is_empty() {
        push(
            BinaryRule::LoggingApi,
            format!(
                "imports {}: NSLog and NSLogv write to the system log, print, debugPrint and \
                 printf to standard output; what is logged is not established",
                logging.join(", ")
            ),
        );
    }
    let unprotected = named(&FILE_PROTECTION_NONE);
    if !unprotected.is_empty() {
        push(
            BinaryRule::FileProtectionNone,
            format!(
                "imports {}: files given this protection class stay readable while the device \
                 is locked; which files, and what they hold, is not established",
                unprotected.join(", ")
            ),
        );
    }
    let always = named(&KEYCHAIN_ACCESSIBLE_ALWAYS);
    if !always.is_empty() {
        push(
            BinaryRule::KeychainAccessibleAlways,
            format!(
                "imports {}: keychain items stored with it stay readable while the device is \
                 locked (deprecated since iOS 12); which items is not established",
                always.join(", ")
            ),
        );
    }
    let legacy = named(&UIWEBVIEW_CLASS);
    if !legacy.is_empty() {
        push(
            BinaryRule::UiWebView,
            format!(
                "references {}: deprecated since iOS 12 (no process isolation, JavaScript \
                 cannot be turned off); App Store Connect refuses apps that use it (ITMS-90809)",
                legacy.join(", ")
            ),
        );
    }
}

/// CryptoKit's insecure hashes the image imports, by name (`Insecure.MD5`, `Insecure.SHA1`).
fn insecure_cryptokit_hashes(image: &MachO) -> Vec<&'static str> {
    let Some(symbols) = &image.symbols else {
        return Vec::new();
    };
    let start = symbols
        .imports
        .partition_point(|name| name.as_str() < CRYPTOKIT_INSECURE_PREFIX);
    let insecure = symbols.imports[start..]
        .iter()
        .take_while(|name| name.starts_with(CRYPTOKIT_INSECURE_PREFIX));
    let mut found = Vec::new();
    for name in insecure {
        // Swift mangling: `3MD5V` and `9MD5DigestV` are MD5's types, `4SHA1V` and
        // `10SHA1DigestV` SHA-1's.
        let member = &name[CRYPTOKIT_INSECURE_PREFIX.len()..];
        let hash = if member.starts_with("3MD5V") || member.starts_with("9MD5DigestV") {
            "Insecure.MD5"
        } else if member.starts_with("4SHA1V") || member.starts_with("10SHA1DigestV") {
            "Insecure.SHA1"
        } else {
            continue;
        };
        if !found.contains(&hash) {
            found.push(hash);
        }
    }
    found.sort_unstable();
    found
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
        let signer = check
            .signer
            .as_ref()
            .map(|signer| signer_problems(check, signer))
            .unwrap_or_default();
        for (rule, detail) in detail.into_iter().chain(signer) {
            findings.push(BinaryFinding {
                rule,
                binary: binary.path.clone(),
                architecture: architecture.clone(),
                detail,
            });
        }
    }
}

/// The two encodings of a signature's entitlements must agree: iOS 15 and later read the DER
/// ones, earlier releases and most tools the XML ones, so a difference lets an app show one set
/// and run with another.
fn entitlement_checks(image: &MachO, push: &mut impl FnMut(BinaryRule, String)) {
    let Some(Ok(signature)) = &image.signature else {
        return;
    };
    let Some(der) = signature.der_entitlements_decoded() else {
        return;
    };
    let der = match der {
        Ok(der) => der,
        Err(error) => {
            push(
                BinaryRule::EntitlementsDiffer,
                format!(
                    "the DER entitlements cannot be read ({error}): iOS 15 and later read them"
                ),
            );
            return;
        }
    };
    let xml = signature
        .entitlements
        .as_ref()
        .and_then(|entitlements| entitlements.plist.as_ref().ok())
        .and_then(|plist| plist.root.as_dictionary());
    match xml {
        Some(xml) if !same_entitlements(&der.dictionary, xml) => {
            let mut keys: Vec<&str> = der
                .dictionary
                .iter()
                .map(|(key, _)| key)
                .chain(xml.iter().map(|(key, _)| key))
                .filter(|key| {
                    let (left, right) = (der.dictionary.get(key), xml.get(key));
                    match (left, right) {
                        (Some(left), Some(right)) => {
                            !same_entitlements(&single(key, left), &single(key, right))
                        }
                        _ => true,
                    }
                })
                .collect();
            keys.sort_unstable();
            keys.dedup();
            push(
                BinaryRule::EntitlementsDiffer,
                format!(
                    "the DER entitlements (read by iOS 15 and later) differ from the XML ones in \
                     {}",
                    keys.join(", ")
                ),
            );
        }
        _ => {}
    }
}

/// A one-key dictionary, to compare two values with the entitlements' own equality.
fn single(key: &str, value: &Value) -> crate::plist::Dictionary {
    let mut dictionary = crate::plist::Dictionary::default();
    dictionary.insert_first(key.to_owned(), value.clone());
    dictionary
}

/// What is wrong with who signed a slice: a CMS signature that does not verify (nothing else
/// about the signer can then be trusted), else a chain not anchored to Apple and a team the
/// certificate does not have.
fn signer_problems(check: &super::SignatureCheck, signer: &Signer) -> Vec<(BinaryRule, String)> {
    let named = signer
        .common_name
        .as_deref()
        .unwrap_or("an unnamed certificate");
    if let Err(problem) = &signer.signature {
        // An algorithm msec does not verify is not a failed signature: the signer checks did
        // not run, which `coverage::unchecked` reports so the rules stay incomplete.
        if problem.unsupported() {
            return Vec::new();
        }
        return vec![(
            BinaryRule::CmsSignatureInvalid,
            format!("the CMS signature by {named} does not verify: {problem}"),
        )];
    }
    let mut problems = Vec::new();
    // A chain that reaches Apple's root through a link msec cannot verify is unchecked, not
    // broken (`coverage::unchecked`).
    if !signer.apple_anchored && !signer.anchor_unverified() {
        let broken = signer
            .chain
            .iter()
            .take(signer.chain.len().saturating_sub(1))
            .find(|link| link.verified_by_next != Some(true));
        let detail = match (broken, signer.chain.last()) {
            (Some(link), _) => format!(
                "signed by {named}; the chain breaks at {}: its issuer's signature does not \
                 verify",
                link.common_name
                    .as_deref()
                    .unwrap_or("an unnamed certificate")
            ),
            (None, Some(last)) => format!(
                "signed by {named}; the chain ends at {}, which is not one of Apple's root \
                 certificates",
                last.common_name
                    .as_deref()
                    .unwrap_or("an unnamed certificate")
            ),
            (None, None) => format!("signed by {named}; the signer's certificate cannot be read"),
        };
        problems.push((BinaryRule::SignerNotApple, detail));
    }
    if let (Some(directory_team), Some(certificate_team)) = (&check.team_id, &signer.team_id)
        && directory_team != certificate_team
    {
        problems.push((
            BinaryRule::TeamMismatch,
            format!(
                "the CodeDirectory names team {directory_team}, the certificate ({named}) team \
                 {certificate_team}"
            ),
        ));
    }
    problems
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

/// A check on the app as a whole: its provisioning profile and its App Transport Security
/// configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AppRule {
    /// The provisioning profile cannot be read (msec).
    ProfileUnreadable,
    /// The profile's CMS signature does not verify: it was changed after signing (msec).
    ProfileSignatureInvalid,
    /// The profile is shown not to be Apple's: its signer's chain ends at someone else's root,
    /// or a link is not signed by the certificate it names as issuer. iOS installs only
    /// profiles Apple signed (msec).
    ProfileNotApple,
    /// The profile has expired: iOS no longer launches the app (msec).
    ProfileExpired,
    /// The profile provisions a different bundle identifier (msec).
    ProfileBundleMismatch,
    /// The app's signature claims entitlements the profile does not allow (msec).
    ProfileEntitlementsMismatch,
    /// The profile distributes the app outside the App Store (development, ad hoc,
    /// enterprise) (msec).
    ProfileDistribution,
    /// The main executable's signing certificate is not among the profile's
    /// `DeveloperCertificates`: iOS does not install the app (msec).
    ProfileCertificateMismatch,
    /// A privacy manifest is invalid: wrong types or missing keys, an unknown category, data
    /// type or purpose, an empty list, tracking without domains (App Store Connect:
    /// ITMS-91056) (msec).
    PrivacyManifestInvalid,
    /// A privacy manifest gives a reason code that is not approved for its category (App
    /// Store Connect: ITMS-91055) (msec).
    PrivacyReasonInvalid,
    /// An executable uses a required-reason API whose category no privacy manifest covering
    /// it declares (App Store Connect: ITMS-91053) (msec).
    RequiredReasonUndeclared,
    /// A framework on Apple's list of commonly used third-party SDKs ships no privacy
    /// manifest (App Store Connect: ITMS-91061) (msec).
    SdkPrivacyManifestMissing,
    /// The signing certificate does not fit the distribution method the provisioning profile
    /// declares: a development certificate on an App Store, ad hoc or in-house build, or a
    /// distribution certificate on a development build (msec).
    CertificateDistributionMismatch,
    /// Code uses a protected resource (by class, method or entitlement) and its bundle's
    /// `Info.plist` has no usable purpose string for it: the request fails or the app is
    /// terminated, and App Store Connect flags the build (ITMS-90683) (msec).
    PurposeStringMissing,
    /// A privacy manifest declares tracking and no executable uses App Tracking Transparency to
    /// ask for permission (App Review guideline 5.1.2) (msec).
    TrackingWithoutAtt,
    /// The build misses an upload requirement in force: the SDK it was built with, or the
    /// lowest iOS version it targets (msec).
    UploadRequirementUnmet,
    /// The build misses an upload requirement Apple has announced (msec).
    UploadRequirementUpcoming,
    /// `NSAllowsArbitraryLoads` is in effect: ATS is off for every connection (MobSF).
    AtsArbitraryLoads,
    /// `NSAllowsArbitraryLoads` is set but iOS 10+ ignores it, because a narrower key is
    /// present (msec refinement of MobSF's check).
    AtsArbitraryLoadsIgnored,
    /// `NSAllowsArbitraryLoadsInWebContent` (MobSF).
    AtsWebContent,
    /// `NSAllowsArbitraryLoadsForMedia` (MobSF).
    AtsMedia,
    /// `NSAllowsLocalNetworking` (MobSF).
    AtsLocalNetworking,
    /// An exception domain allows plain HTTP (MobSF; loopback hosts excepted).
    AtsInsecureHttpDomain,
    /// An exception domain accepts TLS 1.0 or 1.1 (MobSF; TLS 1.2 is the default, not
    /// flagged).
    AtsWeakTlsDomain,
    /// An exception domain does not require forward secrecy (MobSF).
    AtsForwardSecrecyDisabled,
    /// A third-party payment SDK ships in the app and nothing links StoreKit: a lead, since
    /// in-app purchase is required for digital goods only (guideline 3.1.1) (msec). See
    /// [`super::store_leads`] for this and the rules below.
    PaymentSdkWithoutStoreKit,
    /// A third-party login SDK is used and nothing uses Sign in with Apple: a lead, since
    /// guideline 4.8 requires an equivalent privacy-preserving login option, which may be
    /// another, and has exemptions (msec).
    ThirdPartyLoginWithoutEquivalent,
    /// Code creates accounts through a recognised SDK and no recognised deletion call is seen:
    /// a lead (guideline 5.1.1(v)) (msec).
    AccountDeletionNotSeen,
    /// An executable links a library from /System/Library/PrivateFrameworks: non-public API,
    /// which App Store Connect rejects (guideline 2.5.1, ITMS-90338) (msec).
    PrivateFrameworkLinked,
    /// A C string names a path in /System/Library/PrivateFrameworks, as code loading one at
    /// run time would: a lead (msec).
    PrivateFrameworkPath,
    /// The app registers custom URL schemes: any app can register the same scheme, so links to
    /// it can be taken by another app, and its handler must validate what it receives (msec;
    /// a lead, since the handler's validation is not read).
    CustomUrlScheme,
}

impl AppRule {
    /// Engine key.
    pub fn key(self) -> &'static str {
        match self {
            Self::ProfileUnreadable => "msec_ios_profile_unreadable",
            Self::ProfileSignatureInvalid => "msec_ios_profile_signature_invalid",
            Self::ProfileNotApple => "msec_ios_profile_not_apple",
            Self::ProfileExpired => "msec_ios_profile_expired",
            Self::ProfileBundleMismatch => "msec_ios_profile_bundle_mismatch",
            Self::ProfileEntitlementsMismatch => "msec_ios_profile_entitlements_mismatch",
            Self::ProfileDistribution => "msec_ios_profile_distribution",
            Self::ProfileCertificateMismatch => "msec_ios_profile_certificate_mismatch",
            Self::PrivacyManifestInvalid => "msec_ios_privacy_manifest_invalid",
            Self::PrivacyReasonInvalid => "msec_ios_privacy_reason_invalid",
            Self::RequiredReasonUndeclared => "msec_ios_required_reason_undeclared",
            Self::SdkPrivacyManifestMissing => "msec_ios_sdk_privacy_manifest_missing",
            Self::CertificateDistributionMismatch => "msec_ios_certificate_distribution_mismatch",
            Self::PurposeStringMissing => "msec_ios_purpose_string_missing",
            Self::TrackingWithoutAtt => "msec_ios_tracking_without_att",
            Self::UploadRequirementUnmet => "msec_ios_upload_requirement_unmet",
            Self::UploadRequirementUpcoming => "msec_ios_upload_requirement_upcoming",
            Self::AtsArbitraryLoads => "msec_ios_ats_arbitrary_loads",
            Self::AtsArbitraryLoadsIgnored => "msec_ios_ats_arbitrary_loads_ignored",
            Self::AtsWebContent => "msec_ios_ats_web_content",
            Self::AtsMedia => "msec_ios_ats_media",
            Self::AtsLocalNetworking => "msec_ios_ats_local_networking",
            Self::AtsInsecureHttpDomain => "msec_ios_ats_insecure_http_domain",
            Self::AtsWeakTlsDomain => "msec_ios_ats_weak_tls_domain",
            Self::AtsForwardSecrecyDisabled => "msec_ios_ats_forward_secrecy_disabled",
            Self::PaymentSdkWithoutStoreKit => "msec_ios_store_payment_sdk_without_storekit",
            Self::ThirdPartyLoginWithoutEquivalent => "msec_ios_store_third_party_login",
            Self::AccountDeletionNotSeen => "msec_ios_store_account_deletion_not_seen",
            Self::PrivateFrameworkLinked => "msec_ios_private_framework_linked",
            Self::PrivateFrameworkPath => "msec_ios_private_framework_path",
            Self::CustomUrlScheme => "msec_ios_custom_url_scheme",
        }
    }

    /// Severity on MobSF's scale.
    pub fn severity(self) -> Severity {
        match self {
            Self::ProfileUnreadable
            | Self::ProfileSignatureInvalid
            | Self::ProfileNotApple
            | Self::ProfileExpired
            | Self::ProfileBundleMismatch
            | Self::ProfileEntitlementsMismatch
            | Self::ProfileCertificateMismatch
            | Self::PrivacyManifestInvalid
            | Self::PrivacyReasonInvalid
            | Self::RequiredReasonUndeclared
            | Self::SdkPrivacyManifestMissing
            | Self::CertificateDistributionMismatch
            | Self::PurposeStringMissing
            | Self::TrackingWithoutAtt
            | Self::UploadRequirementUnmet
            | Self::AtsArbitraryLoads
            | Self::AtsInsecureHttpDomain
            | Self::AtsWeakTlsDomain
            | Self::PrivateFrameworkLinked => Severity::High,
            Self::AtsWebContent
            | Self::AtsMedia
            | Self::AtsForwardSecrecyDisabled
            | Self::UploadRequirementUpcoming => Severity::Warning,
            Self::ProfileDistribution
            | Self::AtsArbitraryLoadsIgnored
            | Self::AtsLocalNetworking
            | Self::PaymentSdkWithoutStoreKit
            | Self::ThirdPartyLoginWithoutEquivalent
            | Self::AccountDeletionNotSeen
            | Self::PrivateFrameworkPath
            | Self::CustomUrlScheme => Severity::Info,
        }
    }

    /// Where the rule comes from.
    pub fn origin(self) -> Origin {
        match self {
            Self::AtsArbitraryLoads
            | Self::AtsWebContent
            | Self::AtsMedia
            | Self::AtsLocalNetworking
            | Self::AtsInsecureHttpDomain
            | Self::AtsWeakTlsDomain
            | Self::AtsForwardSecrecyDisabled => Origin::MobSf,
            _ => Origin::Msec,
        }
    }

    /// What a finding of this rule rests on, for the store leads and private frameworks;
    /// `None` for the others (profiles, ATS, privacy manifests: declarations, not code).
    pub fn evidence(self) -> Option<BinaryEvidence> {
        match self {
            Self::PaymentSdkWithoutStoreKit
            | Self::ThirdPartyLoginWithoutEquivalent
            | Self::PrivateFrameworkLinked => Some(BinaryEvidence::Import),
            Self::AccountDeletionNotSeen | Self::PrivateFrameworkPath => {
                Some(BinaryEvidence::String)
            }
            _ => None,
        }
    }
}

/// One finding about the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppFinding {
    /// The rule.
    pub rule: AppRule,
    /// The file it concerns (`Payload/A.app/Info.plist`, `.../embedded.mobileprovision`).
    pub location: String,
    /// What it is about: a domain, an entitlement, the profile's kind.
    pub subject: Option<String>,
    /// What triggered it.
    pub detail: String,
}

/// The profile and ATS checks. `today` (`yyyy-MM-dd`) dates the profile's expiry.
pub fn analyse_app(app: &AppBundle, today: &str) -> Vec<AppFinding> {
    let mut findings = Vec::new();
    profile_checks(app, today, &mut findings);
    ats_checks(app, &mut findings);
    privacy_checks(app, &mut findings);
    certificate_use_checks(app, &mut findings);
    purpose_string_checks(app, &mut findings);
    tracking_checks(app, &mut findings);
    upload_requirement_checks(app, today, &mut findings);
    findings.extend(super::store_leads::analyse_store_leads(app));
    url_scheme_checks(app, &mut findings);
    findings
}

/// The app's custom URL schemes (`CFBundleURLSchemes`), one finding naming them all, with
/// whether the app also has universal links (`applinks:` associated domains), which iOS opens
/// only in the app whose domain's file names it.
fn url_scheme_checks(app: &AppBundle, findings: &mut Vec<AppFinding>) {
    let Some(info) = &app.info else {
        return;
    };
    if info.url_schemes.is_empty() {
        return;
    }
    let universal_links = super::associated_domains(app)
        .iter()
        .any(|domain| domain.starts_with("applinks:"));
    findings.push(AppFinding {
        rule: AppRule::CustomUrlScheme,
        location: format!("{}Info.plist", app.path),
        subject: Some(info.url_schemes.join(", ")),
        detail: format!(
            "registers {}: any app can register the same scheme, so a link to it may open \
             another app, and the handler must validate the URL and its source. {}",
            info.url_schemes.join(", "),
            if universal_links {
                "The app also has universal links (applinks), which only it can claim."
            } else {
                "The app has no universal links (applinks associated domains), which only it \
                 could claim."
            }
        ),
    });
}

/// The bundle whose `Info.plist` holds the purpose strings for an executable's code: the
/// innermost app extension, watch app or App Clip containing it, else the app. Frameworks
/// run in the process that loads them, whose bundle's purpose strings iOS shows.
pub(super) fn purpose_bundle<'app>(
    app: &'app AppBundle,
    binary: &str,
) -> (&'app str, Option<&'app super::BundleInfo>) {
    let relative = binary.strip_prefix(app.path.as_str()).unwrap_or(binary);
    let mut owner: Option<&str> = None;
    let mut offset = 0;
    for part in relative.split('/') {
        offset += part.len() + 1;
        if part.ends_with(".appex") || part.ends_with(".app") {
            owner = binary.get(..app.path.len() + offset);
        }
    }
    match owner.and_then(|directory| {
        app.components
            .iter()
            .find(|component| component.path == directory)
    }) {
        Some(component) => (component.path.as_str(), component.info.as_ref()),
        None => (app.path.as_str(), app.info.as_ref()),
    }
}

/// Each protected resource some executable's code uses must have a purpose string in the
/// `Info.plist` of the bundle it runs in (see [`super::purpose_strings`]). One finding per
/// bundle and resource, naming the first executable seen using it. A bundle whose
/// `Info.plist` was not read is not judged.
fn purpose_string_checks(app: &AppBundle, findings: &mut Vec<AppFinding>) {
    use super::purpose_strings::{entitlement_uses, localized_problems, purpose_problem};
    use std::collections::BTreeMap;

    let mut used: BTreeMap<(&str, usize), (String, String, usize)> = BTreeMap::new();
    for binary in &app.binaries {
        let mut uses = binary.protected_resource_uses.clone();
        if let Some(entitlements) = binary
            .entitlements()
            .and_then(|plist| plist.as_ref().ok())
            .and_then(|plist| plist.root.as_dictionary())
        {
            uses.extend(entitlement_uses(entitlements));
        }
        let (directory, _) = purpose_bundle(app, &binary.path);
        for resource_use in uses {
            let relative = binary
                .path
                .strip_prefix(app.path.as_str())
                .unwrap_or(&binary.path)
                .to_owned();
            used.entry((directory, resource_use.requirement))
                .and_modify(|(.., others)| *others += 1)
                .or_insert((relative, resource_use.evidence, 0));
        }
    }
    for ((directory, requirement), (binary, evidence, others)) in used {
        let requirement = &super::purpose_strings::REQUIREMENTS[requirement];
        let more = match others {
            0 => String::new(),
            1 => " (and 1 more executable)".to_owned(),
            count => format!(" (and {count} more executables)"),
        };
        let user = format!("{binary}{more} uses {} ({evidence})", requirement.resource);
        if let Some(info) = purpose_bundle(app, directory).1
            && let Some(problem) =
                purpose_problem(requirement, &info.usage_descriptions, &info.wrong_types)
        {
            findings.push(AppFinding {
                rule: AppRule::PurposeStringMissing,
                location: format!("{directory}Info.plist"),
                subject: Some(requirement.keys[0].to_owned()),
                detail: format!("{problem}; {user}"),
            });
        }
        // Each localization of this bundle that sets one of the keys must set a usable text:
        // iOS shows it instead of Info.plist's in that language.
        for localized in app
            .localized_info
            .iter()
            .filter(|localized| localized.bundle == directory)
        {
            let Ok(strings) = &localized.strings else {
                continue;
            };
            for (key, problem) in localized_problems(requirement, strings) {
                findings.push(AppFinding {
                    rule: AppRule::PurposeStringMissing,
                    location: localized.path.clone(),
                    subject: Some(key.to_owned()),
                    detail: format!(
                        "{problem} in the {} localization; {user}",
                        localized.language
                    ),
                });
            }
        }
    }
}

/// A privacy manifest that declares tracking (`NSPrivacyTracking`, or a collected data type
/// used for tracking) commits the app to asking first through App Tracking Transparency.
/// When no executable references `ATTrackingManager`, nothing in the app can ask. The class
/// reference is read from the symbol table, which App Store encryption leaves readable.
fn tracking_checks(app: &AppBundle, findings: &mut Vec<AppFinding>) {
    let asks = app
        .binaries
        .iter()
        .flat_map(|binary| binary.images())
        .any(|image| image.imports("_OBJC_CLASS_$_ATTrackingManager"));
    if asks {
        return;
    }
    for manifest in &app.privacy_manifests {
        let declared = if manifest.tracking == Some(true) {
            "NSPrivacyTracking is true".to_owned()
        } else if let Some(entry) = manifest
            .collected_data_types
            .iter()
            .find(|entry| entry.tracking == Some(true))
        {
            format!(
                "{} is collected for tracking",
                entry.data_type.as_deref().unwrap_or("a data type")
            )
        } else {
            continue;
        };
        findings.push(AppFinding {
            rule: AppRule::TrackingWithoutAtt,
            location: manifest.path.clone(),
            subject: None,
            detail: format!(
                "{declared}, but no executable uses App Tracking Transparency (ATTrackingManager) to ask the user's permission, which tracking requires"
            ),
        });
    }
}

/// The app's SDK and minimum iOS version against App Store Connect's upload requirements on
/// `today` (see [`super::upload_requirements`]). Missing keys are not findings: they are
/// reported as unchecked by [`super::coverage::unchecked`].
fn upload_requirement_checks(app: &AppBundle, today: &str, findings: &mut Vec<AppFinding>) {
    let Some(info) = &app.info else {
        return;
    };
    let Ok(problems) = super::upload_requirements::upload_problems(info, today) else {
        return;
    };
    for problem in problems {
        findings.push(AppFinding {
            rule: if problem.in_force {
                AppRule::UploadRequirementUnmet
            } else {
                AppRule::UploadRequirementUpcoming
            },
            location: format!("{}Info.plist", app.path),
            // The required version is part of the subject: a stricter requirement is a new
            // finding, not the old one changed.
            subject: Some(format!(
                "{} {}.{}",
                problem.constraint.key(),
                problem.required.0,
                problem.required.1
            )),
            detail: problem.to_string(),
        });
    }
}

/// The signing certificate must fit the distribution method the provisioning profile declares:
/// development certificates sign development builds; App Store, ad hoc and in-house builds are
/// signed with a distribution certificate. A development certificate in a development build is
/// what it should be, not a finding. Only a profile Apple issued states the intended method;
/// without one (App Store downloads carry none, a forged one proves nothing) nothing is
/// reported. Only a code signature that verifies counts.
fn certificate_use_checks(app: &AppBundle, findings: &mut Vec<AppFinding>) {
    findings.extend(certificate_distribution_mismatch(
        app,
        &super::distribution::of(app),
    ));
}

/// The certificate check against a given distribution method: a finding when the main
/// executable's verified signer is a development certificate on an ad hoc, in-house or App
/// Store build, or a distribution certificate on a development build. Nothing when the method
/// is not established. [`analyse_app`] passes the method an Apple-issued profile establishes.
pub fn certificate_distribution_mismatch(
    app: &AppBundle,
    distribution: &super::distribution::Distribution,
) -> Option<AppFinding> {
    use super::distribution::Distribution;
    use super::profile::ProfileKind;
    use crate::macho::signer::CertificateUse;

    // Only a profile Apple issued establishes the method (`distribution::of`); otherwise the
    // check is unchecked (`coverage::unchecked`), not judged against an untrusted claim.
    let (Distribution::Established { kind, profile }, Some(main)) =
        (distribution, app.binaries.first())
    else {
        return None;
    };
    let kind = *kind;
    let signer = main
        .signatures
        .first()
        .and_then(|check| check.signer.as_ref())
        .filter(|signer| signer.signature.is_ok())?;
    let fits = match (kind, signer.certificate_use) {
        (ProfileKind::Development, CertificateUse::Development)
        | (
            ProfileKind::AdHoc | ProfileKind::Enterprise | ProfileKind::AppStore,
            CertificateUse::Distribution,
        ) => true,
        // Apple's App Store re-signing, Developer ID and unrecognised names are not judged
        // here (a certificate Apple did not issue is AC-IOS-0030's subject).
        (_, CertificateUse::AppStore | CertificateUse::DeveloperId | CertificateUse::Other) => true,
        _ => false,
    };
    if fits {
        return None;
    }
    let named = signer
        .common_name
        .clone()
        .unwrap_or_else(|| "the signing certificate".to_owned());
    let detail = match kind {
        ProfileKind::AppStore => format!(
            "{named}, a development certificate, signed a build whose profile distributes it \
             through the App Store: App Store Connect accepts only builds signed with a \
             distribution certificate"
        ),
        ProfileKind::AdHoc | ProfileKind::Enterprise => format!(
            "{named}, a development certificate, signed a build whose profile is for {} \
             distribution, which uses a distribution certificate",
            kind.label().to_lowercase()
        ),
        ProfileKind::Development => format!(
            "{named}, a distribution certificate, signed a build whose profile is for \
             development, which uses a development certificate"
        ),
    };
    Some(AppFinding {
        rule: AppRule::CertificateDistributionMismatch,
        location: profile.clone(),
        subject: Some(named),
        detail,
    })
}

/// The bundle directory whose privacy manifests cover a binary: a framework's or an app
/// extension's own directory, else the app's (the main executable and loose libraries).
fn owning_bundle<'path>(app: &'path AppBundle, binary: &'path str) -> &'path str {
    let relative = binary.strip_prefix(app.path.as_str()).unwrap_or(binary);
    let mut owner = app.path.len();
    let mut offset = 0;
    for part in relative.split('/') {
        offset += part.len() + 1;
        if part.ends_with(".framework") || part.ends_with(".appex") {
            owner = app.path.len() + offset;
        }
    }
    &binary[..owner.min(binary.len())]
}

/// The manifests that declare for the code of bundle `directory`: its own
/// `PrivacyInfo.xcprivacy`, and those of resource bundles directly inside it (where static
/// SDKs linked into its executable keep theirs).
fn covering_manifests<'app>(
    app: &'app AppBundle,
    directory: &str,
) -> Vec<&'app super::PrivacyManifest> {
    app.privacy_manifests
        .iter()
        .filter(|manifest| {
            let Some(relative) = manifest.path.strip_prefix(directory) else {
                return false;
            };
            relative == "PrivacyInfo.xcprivacy"
                || relative
                    .strip_suffix("/PrivacyInfo.xcprivacy")
                    .is_some_and(|bundle| bundle.ends_with(".bundle") && !bundle.contains('/'))
        })
        .collect()
}

fn privacy_checks(app: &AppBundle, findings: &mut Vec<AppFinding>) {
    use super::required_reason::{Category, ManifestProblem, listed_sdk, manifest_problems};

    for manifest in &app.privacy_manifests {
        for problem in manifest_problems(manifest) {
            let rule = match problem {
                ManifestProblem::InvalidReason { .. } => AppRule::PrivacyReasonInvalid,
                _ => AppRule::PrivacyManifestInvalid,
            };
            findings.push(AppFinding {
                rule,
                location: manifest.path.clone(),
                subject: None,
                detail: problem.to_string(),
            });
        }
        if let Some(problem) = &manifest.problem {
            findings.push(AppFinding {
                rule: AppRule::PrivacyManifestInvalid,
                location: manifest.path.clone(),
                subject: None,
                detail: format!("the manifest cannot be read as a property list: {problem}"),
            });
        }
    }
    for binary in &app.binaries {
        if binary.required_reason_apis.is_empty() {
            continue;
        }
        let directory = owning_bundle(app, &binary.path);
        let mut manifests = covering_manifests(app, directory);
        // Extensions: Apple documents no manifest placement for them, so the app's manifests
        // count too rather than report an undocumented requirement.
        if directory.ends_with(".appex/") {
            manifests.extend(covering_manifests(app, &app.path));
        }
        let declared: Vec<Category> = manifests
            .iter()
            .flat_map(|manifest| &manifest.accessed_api_types)
            .filter_map(|entry| entry.category.as_deref().and_then(Category::of_key))
            .collect();
        for category in Category::ALL {
            let uses: Vec<&super::required_reason::ApiUse> = binary
                .required_reason_apis
                .iter()
                .filter(|api| api.category == category)
                .collect();
            if uses.is_empty() || declared.contains(&category) {
                continue;
            }
            let evidence: Vec<&str> = uses.iter().map(|api| api.evidence.as_str()).collect();
            let covering = if manifests.is_empty() {
                format!("no privacy manifest covers {directory}")
            } else {
                format!(
                    "{} does not declare it",
                    manifests
                        .iter()
                        .map(|manifest| manifest.path.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            findings.push(AppFinding {
                rule: AppRule::RequiredReasonUndeclared,
                location: binary.path.clone(),
                subject: Some(category.key().to_owned()),
                detail: format!(
                    "uses {} ({}); {covering}",
                    uses.iter()
                        .map(|api| api.api)
                        .collect::<Vec<_>>()
                        .join(", "),
                    evidence.join(", ")
                ),
            });
        }
    }
    for component in &app.components {
        let Some(name) = component
            .path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .and_then(|last| last.strip_suffix(".framework"))
        else {
            continue;
        };
        let Some(sdk) = listed_sdk(name) else {
            continue;
        };
        let has_manifest = app
            .privacy_manifests
            .iter()
            .any(|manifest| manifest.path.starts_with(component.path.as_str()));
        if !has_manifest {
            findings.push(AppFinding {
                rule: AppRule::SdkPrivacyManifestMissing,
                location: component.path.clone(),
                subject: Some(sdk.to_owned()),
                detail: format!(
                    "{sdk} is on Apple's list of commonly used third-party SDKs, which must \
                     ship their own privacy manifest; {} has none",
                    component.path
                ),
            });
        }
    }
}

fn profile_checks(app: &AppBundle, today: &str, findings: &mut Vec<AppFinding>) {
    use super::profile::{ProfileKind, entitlement_mismatches};

    let (Some(location), Some(profile)) = (&app.provisioning_profile, &app.profile) else {
        return;
    };
    let mut push = |rule: AppRule, subject: Option<String>, detail: String| {
        findings.push(AppFinding {
            rule,
            location: location.clone(),
            subject,
            detail,
        });
    };
    let profile = match profile {
        Ok(profile) => profile,
        Err(error) => {
            push(AppRule::ProfileUnreadable, None, error.to_string());
            return;
        }
    };
    // Only what is shown is a finding: a signature that fails over the content, a chain that
    // fails or ends at someone else's root. What leaves Apple's authorship merely not
    // established (an incomplete chain, an unpinned root named as Apple's, an algorithm msec
    // does not verify, a signer without the undocumented profile-signing extension) is
    // reported by `coverage::unchecked` instead.
    if let Err(problem) = profile
        .signature
        .trusted(&super::profile::ProfileTrust::APPLE)
        && problem.proven()
    {
        let rule = match problem {
            super::profile::ProfileTrustProblem::NotVerified(_) => AppRule::ProfileSignatureInvalid,
            _ => AppRule::ProfileNotApple,
        };
        push(
            rule,
            None,
            format!("the provisioning profile is not Apple's: {problem}"),
        );
    }
    if profile.expired(today) == Some(true) {
        let date = profile.expires_on().unwrap_or_default();
        push(
            AppRule::ProfileExpired,
            Some(date.clone()),
            format!("the provisioning profile expired on {date}: iOS no longer launches the app"),
        );
    }
    if let Some(identifier) = app
        .info
        .as_ref()
        .and_then(|info| info.identifier.as_deref())
        && profile.covers_bundle(identifier) == Some(false)
    {
        push(
            AppRule::ProfileBundleMismatch,
            Some(identifier.to_owned()),
            format!(
                "the profile provisions {}, not {identifier}",
                profile
                    .application_identifier()
                    .unwrap_or("no application identifier")
            ),
        );
    }
    let app_entitlements = app
        .binaries
        .first()
        .and_then(|binary| binary.entitlements())
        .and_then(|plist| plist.as_ref().ok())
        .and_then(|plist| plist.root.as_dictionary());
    if let (Some(allowed), Some(claimed)) = (profile.entitlements(), app_entitlements) {
        for mismatch in entitlement_mismatches(allowed, claimed) {
            push(
                AppRule::ProfileEntitlementsMismatch,
                Some(mismatch.key),
                mismatch.reason,
            );
        }
    }
    // The certificate that signed the main executable must be one the profile allows. Only
    // a signature that verifies counts: a broken one is reported as such.
    let signer_leaf = app
        .binaries
        .first()
        .and_then(|binary| binary.signatures.first())
        .and_then(|check| check.signer.as_ref())
        .filter(|signer| signer.signature.is_ok())
        .and_then(|signer| signer.leaf().map(|leaf| (signer, leaf)));
    if let Some((signer, leaf)) = signer_leaf
        && !profile.developer_certificates.is_empty()
        && !profile
            .developer_certificates
            .iter()
            .any(|allowed| allowed.sha256 == leaf.sha256)
    {
        let named = signer
            .common_name
            .clone()
            .unwrap_or_else(|| leaf.subject.clone());
        push(
            AppRule::ProfileCertificateMismatch,
            Some(named.clone()),
            format!(
                "{named} signed the app, but the profile allows only {} other certificate(s): \
                 iOS does not install it",
                profile.developer_certificates.len()
            ),
        );
    }
    let kind = profile.kind();
    if kind != ProfileKind::AppStore {
        let devices = profile.provisioned_devices.len();
        let detail = match kind {
            ProfileKind::Enterprise => {
                "an enterprise (in-house) profile: installs on any device, outside the App Store"
                    .to_owned()
            }
            _ => format!(
                "a {} profile for {devices} device{}: not an App Store build",
                kind.label(),
                if devices == 1 { "" } else { "s" }
            ),
        };
        push(
            AppRule::ProfileDistribution,
            Some(kind.label().to_owned()),
            detail,
        );
    }
}

fn ats_checks(app: &AppBundle, findings: &mut Vec<AppFinding>) {
    let Some(ats) = &app.transport_security else {
        return;
    };
    let location = format!("{}Info.plist", app.path);
    let mut push = |rule: AppRule, subject: Option<String>, detail: String| {
        findings.push(AppFinding {
            rule,
            location: location.clone(),
            subject,
            detail,
        });
    };
    let minimum_os = app
        .info
        .as_ref()
        .and_then(|info| info.minimum_os_version.as_deref());
    if ats.allows_arbitrary_loads == Some(true) {
        if ats.arbitrary_loads_effective(minimum_os) {
            push(
                AppRule::AtsArbitraryLoads,
                None,
                "NSAllowsArbitraryLoads is true: App Transport Security is off for every \
                 connection (plain HTTP and weak TLS allowed)"
                    .to_owned(),
            );
        } else if let Some(key) = ats.arbitrary_loads_overridden_by() {
            push(
                AppRule::AtsArbitraryLoadsIgnored,
                None,
                format!(
                    "NSAllowsArbitraryLoads is true but {key} is present, so iOS 10 and later \
                     ignore it"
                ),
            );
        }
    }
    let flags = [
        (
            ats.allows_arbitrary_loads_in_web_content,
            AppRule::AtsWebContent,
            "NSAllowsArbitraryLoadsInWebContent is true: web views load any content over plain \
             HTTP or weak TLS",
        ),
        (
            ats.allows_arbitrary_loads_for_media,
            AppRule::AtsMedia,
            "NSAllowsArbitraryLoadsForMedia is true: AVFoundation media loads over plain HTTP \
             or weak TLS",
        ),
        (
            ats.allows_local_networking,
            AppRule::AtsLocalNetworking,
            "NSAllowsLocalNetworking is true: local hosts (.local names, unqualified names, IP \
             addresses) are reached without ATS",
        ),
    ];
    for (value, rule, detail) in flags {
        if value == Some(true) {
            push(rule, None, detail.to_owned());
        }
    }
    for domain in &ats.exception_domains {
        let scope = if domain.includes_subdomains {
            format!("{} and its subdomains", domain.domain)
        } else {
            domain.domain.clone()
        };
        if let Some(key) = &domain.insecure_http
            && !domain.is_loopback()
        {
            push(
                AppRule::AtsInsecureHttpDomain,
                Some(domain.domain.clone()),
                format!("{key}: plain HTTP allowed for {scope}"),
            );
        }
        if domain.weak_tls() {
            push(
                AppRule::AtsWeakTlsDomain,
                Some(domain.domain.clone()),
                format!(
                    "{} accepted for {scope} (ATS requires TLS 1.2 by default)",
                    domain.minimum_tls.as_deref().unwrap_or_default()
                ),
            );
        }
        if domain.requires_forward_secrecy == Some(false) {
            push(
                AppRule::AtsForwardSecrecyDisabled,
                Some(domain.domain.clone()),
                format!("forward secrecy not required for {scope}"),
            );
        }
    }
}
