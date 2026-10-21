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
            | Self::GetTaskAllow
            | Self::CmsSignatureInvalid
            | Self::SignerNotApple
            | Self::TeamMismatch
            | Self::EntitlementsDiffer => Origin::Msec,
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
    // Either encoding counts: iOS 15 and later read the DER entitlements, earlier releases the
    // XML ones.
    let debuggable = |main: &BundleBinary| {
        let xml = matches!(
            main.entitlements(),
            Some(Ok(entitlements)) if entitlements.root.get("get-task-allow") == Some(&Value::Boolean(true))
        );
        let der = main.images().any(|image| {
            matches!(&image.signature, Some(Ok(signature)) if matches!(
                signature.der_entitlements_decoded(),
                Some(Ok(der)) if der.dictionary.get("get-task-allow") == Some(&Value::Boolean(true))
            ))
        });
        xml || der
    };
    if let Some(main) = app.binaries.first()
        && debuggable(main)
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
        entitlement_checks(image, &mut push);
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
        return vec![(
            BinaryRule::CmsSignatureInvalid,
            format!("the CMS signature by {named} does not verify: {problem}"),
        )];
    }
    let mut problems = Vec::new();
    if !signer.apple_anchored {
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
}

impl AppRule {
    /// Engine key.
    pub fn key(self) -> &'static str {
        match self {
            Self::ProfileUnreadable => "msec_ios_profile_unreadable",
            Self::ProfileSignatureInvalid => "msec_ios_profile_signature_invalid",
            Self::ProfileExpired => "msec_ios_profile_expired",
            Self::ProfileBundleMismatch => "msec_ios_profile_bundle_mismatch",
            Self::ProfileEntitlementsMismatch => "msec_ios_profile_entitlements_mismatch",
            Self::ProfileDistribution => "msec_ios_profile_distribution",
            Self::ProfileCertificateMismatch => "msec_ios_profile_certificate_mismatch",
            Self::PrivacyManifestInvalid => "msec_ios_privacy_manifest_invalid",
            Self::PrivacyReasonInvalid => "msec_ios_privacy_reason_invalid",
            Self::RequiredReasonUndeclared => "msec_ios_required_reason_undeclared",
            Self::SdkPrivacyManifestMissing => "msec_ios_sdk_privacy_manifest_missing",
            Self::AtsArbitraryLoads => "msec_ios_ats_arbitrary_loads",
            Self::AtsArbitraryLoadsIgnored => "msec_ios_ats_arbitrary_loads_ignored",
            Self::AtsWebContent => "msec_ios_ats_web_content",
            Self::AtsMedia => "msec_ios_ats_media",
            Self::AtsLocalNetworking => "msec_ios_ats_local_networking",
            Self::AtsInsecureHttpDomain => "msec_ios_ats_insecure_http_domain",
            Self::AtsWeakTlsDomain => "msec_ios_ats_weak_tls_domain",
            Self::AtsForwardSecrecyDisabled => "msec_ios_ats_forward_secrecy_disabled",
        }
    }

    /// Severity on MobSF's scale.
    pub fn severity(self) -> Severity {
        match self {
            Self::ProfileUnreadable
            | Self::ProfileSignatureInvalid
            | Self::ProfileExpired
            | Self::ProfileBundleMismatch
            | Self::ProfileEntitlementsMismatch
            | Self::ProfileCertificateMismatch
            | Self::PrivacyManifestInvalid
            | Self::PrivacyReasonInvalid
            | Self::RequiredReasonUndeclared
            | Self::SdkPrivacyManifestMissing
            | Self::AtsArbitraryLoads
            | Self::AtsInsecureHttpDomain
            | Self::AtsWeakTlsDomain => Severity::High,
            Self::AtsWebContent | Self::AtsMedia | Self::AtsForwardSecrecyDisabled => {
                Severity::Warning
            }
            Self::ProfileDistribution
            | Self::AtsArbitraryLoadsIgnored
            | Self::AtsLocalNetworking => Severity::Info,
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
    findings
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
    if let Err(problem) = &profile.signature.verified {
        push(
            AppRule::ProfileSignatureInvalid,
            None,
            format!("the profile's CMS signature does not verify ({problem:?})"),
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
