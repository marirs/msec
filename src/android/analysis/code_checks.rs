//! Checks on what an app's DEX code refers to (msec origin; MobSF runs pattern rules on
//! decompiled sources instead). Each finding names the API and the app methods that call it,
//! the way Google Play's release dashboard lists them:
//!
//! - framework APIs the app calls that Android deprecated, or removed (calls then fail);
//! - for apps targeting API 35+, the window APIs Android 15 deprecated for edge-to-edge
//!   (`setStatusBarColor` and friends no longer have an effect), and no sign that the app handles
//!   window insets at all;
//! - `BitmapFactory` decodes without `BitmapFactory.Options`, which load images at full
//!   resolution;
//! - an estimate of how much of the code is obfuscated, for Google Play's requirement of at least
//!   25% optimization, obfuscation and shrinking for apps with more than 10 MB of DEX code (50
//!   MB for games), enforced from February 2027.
//!
//! References are what code names, not data flow: a call guarded by a version check is still
//! a call, and a decode given a `null` `Options` is not found.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::Severity;
use crate::android::api::{self, ApiChange, AppClasses};
use crate::android::dex::{DexEntry, DexFile, Target};
use crate::android::manifest::Manifest;
use crate::android::xml::{XmlDocument, framework_attribute_name};

/// Calling methods listed per finding; the rest are counted.
const MAX_CALLERS: usize = 20;
/// Android 15: edge-to-edge by default for apps targeting it.
const EDGE_TO_EDGE_FROM: u32 = 35;
/// Google Play's DEX size floors for the optimization requirement.
const PLAY_DEX_THRESHOLD_APPS: u64 = 10 * 1024 * 1024;
const PLAY_DEX_THRESHOLD_GAMES: u64 = 50 * 1024 * 1024;
/// Google Play's minimum share for each of optimization, obfuscation and shrinking.
pub const PLAY_DEX_MINIMUM_PERCENT: u32 = 25;

/// Window APIs Android 15 deprecated for edge-to-edge: they have no effect there.
const EDGE_TO_EDGE_DEPRECATED: [&str; 3] = [
    "Landroid/view/Window;->setStatusBarColor(I)V",
    "Landroid/view/Window;->setNavigationBarColor(I)V",
    "Landroid/view/Window;->setNavigationBarDividerColor(I)V",
];

/// Calls that show an app lays itself out edge to edge or handles window insets.
const INSET_HANDLING: [&str; 6] = [
    "Landroidx/activity/EdgeToEdge;->enable",
    "Landroidx/core/view/WindowCompat;->setDecorFitsSystemWindows",
    "Landroid/view/Window;->setDecorFitsSystemWindows",
    "Landroidx/core/view/ViewCompat;->setOnApplyWindowInsetsListener",
    "Landroid/view/View;->setOnApplyWindowInsetsListener",
    "Landroidx/compose/foundation/layout/WindowInsets",
];

/// `BitmapFactory` decodes that take no `BitmapFactory.Options`, so cannot downsample.
const BITMAP_WITHOUT_OPTIONS: [&str; 5] = [
    "Landroid/graphics/BitmapFactory;->decodeFile(Ljava/lang/String;)Landroid/graphics/Bitmap;",
    "Landroid/graphics/BitmapFactory;->decodeResource(Landroid/content/res/Resources;I)Landroid/graphics/Bitmap;",
    "Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;)Landroid/graphics/Bitmap;",
    "Landroid/graphics/BitmapFactory;->decodeByteArray([BII)Landroid/graphics/Bitmap;",
    "Landroid/graphics/BitmapFactory;->decodeFileDescriptor(Ljava/io/FileDescriptor;)Landroid/graphics/Bitmap;",
];

/// A code check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeRule {
    /// A framework API Android deprecated.
    DeprecatedApi,
    /// A framework API Android removed from the public SDK: calls fail on the releases without
    /// it.
    RemovedApi,
    /// A window API Android 15 deprecated for edge-to-edge, in an app targeting API 35+.
    EdgeToEdgeDeprecatedApi,
    /// An app targeting API 35+ with no call that handles window insets or enables
    /// edge-to-edge: content may sit under the system bars on Android 15+.
    EdgeToEdgeNotHandled,
    /// A `BitmapFactory` decode without `BitmapFactory.Options` (no downsampling).
    BitmapWithoutDownsampling,
    /// Less than Google Play's minimum share of the code is obfuscated (estimated from class
    /// names), in an app whose DEX size makes the requirement apply.
    ObfuscationBelowPlayThreshold,
}

impl CodeRule {
    /// Engine key.
    pub fn key(self) -> &'static str {
        match self {
            Self::DeprecatedApi => "msec_code_deprecated_api",
            Self::RemovedApi => "msec_code_removed_api",
            Self::EdgeToEdgeDeprecatedApi => "msec_store_edge_to_edge_deprecated_api",
            Self::EdgeToEdgeNotHandled => "msec_store_edge_to_edge_not_handled",
            Self::BitmapWithoutDownsampling => "msec_store_bitmap_without_downsampling",
            Self::ObfuscationBelowPlayThreshold => "msec_store_dex_obfuscation_below_threshold",
        }
    }

    /// Severity on MobSF's scale.
    pub fn severity(self) -> Severity {
        match self {
            Self::RemovedApi | Self::ObfuscationBelowPlayThreshold => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

/// One finding: the API concerned (absent for app-wide findings) and who calls it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeFinding {
    /// The rule.
    pub rule: CodeRule,
    /// The API in DEX notation (`Landroid/view/Window;->setStatusBarColor(I)V`).
    pub api: Option<String>,
    /// Calling methods in DEX notation, sorted, up to 20.
    pub callers: Vec<String>,
    /// All calling methods, listed or not.
    pub caller_count: usize,
    /// What it means, in words.
    pub detail: String,
}

/// How much of an app's code looks obfuscated, against Google Play's requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexOptimization {
    /// Uncompressed size of all DEX files.
    pub dex_bytes: u64,
    /// The DEX size above which Google Play enforces its requirement for this app.
    pub play_threshold_bytes: u64,
    /// Classes defined.
    pub classes: usize,
    /// Classes whose name looks obfuscated (`a`, `b0`, `aa`).
    pub obfuscated_classes: usize,
    /// An R8 marker is present: the code went through R8, which shrinks and optimizes.
    pub r8: bool,
}

impl DexOptimization {
    /// Obfuscated classes, as a whole percentage of all classes.
    pub fn obfuscated_percent(&self) -> u32 {
        if self.classes == 0 {
            return 0;
        }
        (self.obfuscated_classes * 100 / self.classes) as u32
    }

    /// Google Play's requirement applies (enough DEX code).
    pub fn play_requirement_applies(&self) -> bool {
        self.dex_bytes > self.play_threshold_bytes
    }
}

/// Estimates obfuscation from class names: R8 renames classes to one or two letters, optionally
/// followed by digits (`a`, `bb`, `l50`). Shrinking and optimization cannot be measured without
/// the unshrunk build; an R8 marker says they ran.
pub fn dex_optimization(
    dex_files: &[DexEntry],
    manifest_document: Option<&XmlDocument>,
) -> DexOptimization {
    let mut classes = 0;
    let mut obfuscated = 0;
    let mut r8 = false;
    for file in dex_files.iter().flat_map(|entry| &entry.container.files) {
        r8 |= file
            .compiler_markers()
            .any(|marker| marker.starts_with("~~R8{"));
        for class in &file.classes {
            let Some(descriptor) = file.class_descriptor(class) else {
                continue;
            };
            classes += 1;
            if looks_obfuscated(descriptor) {
                obfuscated += 1;
            }
        }
    }
    DexOptimization {
        dex_bytes: dex_files.iter().map(|entry| entry.size).sum(),
        play_threshold_bytes: if is_game(manifest_document) {
            PLAY_DEX_THRESHOLD_GAMES
        } else {
            PLAY_DEX_THRESHOLD_APPS
        },
        classes,
        obfuscated_classes: obfuscated,
        r8,
    }
}

/// `Lcom/a/b;` or `La0;`: the simple name (after the package and any outer class) is one or
/// two letters, optionally followed by up to three digits.
fn looks_obfuscated(descriptor: &str) -> bool {
    let Some(name) = descriptor
        .strip_prefix('L')
        .and_then(|name| name.strip_suffix(';'))
    else {
        return false;
    };
    let simple = name.rsplit(['/', '$']).next().unwrap_or(name);
    let letters = simple.chars().take_while(char::is_ascii_alphabetic).count();
    let digits = simple[letters..]
        .chars()
        .all(|character| character.is_ascii_digit());
    (1..=2).contains(&letters) && digits && simple.len() - letters <= 3
}

/// `android:appCategory="game"` (0) or `android:isGame="true"` on `<application>`.
fn is_game(document: Option<&XmlDocument>) -> bool {
    let Some(application) = document
        .and_then(|document| document.root.as_ref())
        .and_then(|root| root.elements_named("application").next())
    else {
        return false;
    };
    application.attributes.iter().any(|attribute| {
        match attribute.resource_id.and_then(framework_attribute_name) {
            Some("appCategory") => attribute.value.as_integer() == Some(0),
            Some("isGame") => attribute.value.as_bool() == Some(true),
            _ => false,
        }
    })
}

/// Runs every code check over the app's DEX files.
pub fn analyse_code(
    dex_files: &[DexEntry],
    manifest: &Manifest,
    manifest_document: Option<&XmlDocument>,
) -> Vec<CodeFinding> {
    let target_sdk = manifest
        .target_sdk()
        .or_else(|| manifest.min_sdk())
        .unwrap_or(1);
    let calls = ReferenceIndex::of(dex_files);
    let mut findings = Vec::new();
    for (api, (change, callers)) in &calls.framework {
        let (rule, detail) = match (change.removed_in, change.deprecated_in) {
            (Some(removed), _) => (
                CodeRule::RemovedApi,
                format!(
                    "removed in API {removed}: calls fail on Android releases from API {removed}"
                ),
            ),
            (None, Some(deprecated)) => (
                CodeRule::DeprecatedApi,
                format!("deprecated in API {deprecated}"),
            ),
            (None, None) => continue,
        };
        findings.push(finding(rule, Some(api), callers, detail));
    }
    if target_sdk >= EDGE_TO_EDGE_FROM {
        for api in EDGE_TO_EDGE_DEPRECATED {
            if let Some(callers) = calls.direct.get(api) {
                let detail = "deprecated in API 35; has no effect on Android 15+, where apps \
                              targeting API 35 are edge-to-edge"
                    .to_owned();
                findings.push(finding(
                    CodeRule::EdgeToEdgeDeprecatedApi,
                    Some(api),
                    callers,
                    detail,
                ));
            }
        }
        let handles_insets = calls
            .direct
            .keys()
            .any(|api| INSET_HANDLING.iter().any(|prefix| api.starts_with(prefix)));
        if !handles_insets {
            findings.push(CodeFinding {
                rule: CodeRule::EdgeToEdgeNotHandled,
                api: None,
                callers: Vec::new(),
                caller_count: 0,
                detail: format!(
                    "targets API {target_sdk}, so it is edge-to-edge on Android 15+, and no code \
                     enables edge-to-edge or handles window insets"
                ),
            });
        }
    }
    for api in BITMAP_WITHOUT_OPTIONS {
        if let Some(callers) = calls.direct.get(api) {
            let detail =
                "decodes at full resolution: no BitmapFactory.Options, so no inSampleSize \
                          downsampling"
                    .to_owned();
            findings.push(finding(
                CodeRule::BitmapWithoutDownsampling,
                Some(api),
                callers,
                detail,
            ));
        }
    }
    let optimization = dex_optimization(dex_files, manifest_document);
    if optimization.play_requirement_applies()
        && optimization.obfuscated_percent() < PLAY_DEX_MINIMUM_PERCENT
    {
        findings.push(CodeFinding {
            rule: CodeRule::ObfuscationBelowPlayThreshold,
            api: None,
            callers: Vec::new(),
            caller_count: 0,
            detail: format!(
                "about {}% of {} classes look obfuscated ({}); Google Play requires at least {}% \
                 for apps with more than {} MB of DEX code ({} MB here){}",
                optimization.obfuscated_percent(),
                optimization.classes,
                if optimization.r8 {
                    "R8 ran"
                } else {
                    "no R8 marker: R8 did not run"
                },
                PLAY_DEX_MINIMUM_PERCENT,
                optimization.play_threshold_bytes / (1024 * 1024),
                optimization.dex_bytes / (1024 * 1024),
                ", enforced from February 2027"
            ),
        });
    }
    findings.sort_by(|left, right| (left.rule, &left.api).cmp(&(right.rule, &right.api)));
    findings
}

fn finding(
    rule: CodeRule,
    api: Option<&str>,
    callers: &BTreeSet<String>,
    detail: String,
) -> CodeFinding {
    CodeFinding {
        rule,
        api: api.map(str::to_owned),
        callers: callers.iter().take(MAX_CALLERS).cloned().collect(),
        caller_count: callers.len(),
        detail,
    }
}

/// Who calls what, across all DEX files: references as written (`direct`, by signature) and
/// the deprecated or removed framework APIs they reach (`framework`).
#[derive(Default)]
struct ReferenceIndex {
    direct: HashMap<String, BTreeSet<String>>,
    framework: BTreeMap<String, (ApiChange, BTreeSet<String>)>,
}

impl ReferenceIndex {
    fn of(dex_files: &[DexEntry]) -> Self {
        let files: Vec<&DexFile> = dex_files
            .iter()
            .flat_map(|entry| &entry.container.files)
            .collect();
        let app = app_classes(&files);
        let mut index = Self::default();
        let mut resolved: HashMap<(String, String), Option<api::FrameworkApi>> = HashMap::new();
        for file in files {
            for reference in file.references() {
                let Some((class, member)) = target_parts(file, reference.target) else {
                    continue;
                };
                let Some(caller) = file.method_signature(reference.caller) else {
                    continue;
                };
                let framework = resolved
                    .entry((class.clone(), member.clone()))
                    .or_insert_with(|| api::resolve(&class, &member, &app))
                    .clone();
                index
                    .direct
                    .entry(format!("{class}{member}"))
                    .or_default()
                    .insert(caller.clone());
                if let Some(framework) = framework {
                    index
                        .framework
                        .entry(framework.signature)
                        .or_insert_with(|| (framework.change, BTreeSet::new()))
                        .1
                        .insert(caller);
                }
            }
        }
        index
    }
}

/// `(class, member)` of a reference: `->name(params)return` for methods, `->name` for fields,
/// empty for types (arrays reduced to their element class).
fn target_parts(file: &DexFile, target: Target) -> Option<(String, String)> {
    match target {
        Target::Method(index) => {
            let signature = file.method_signature(index)?;
            let (class, member) = signature.split_once("->")?;
            Some((class.to_owned(), format!("->{member}")))
        }
        Target::Field(index) => {
            let (signature, _) = file.field_signature(index)?;
            let (class, member) = signature.split_once("->")?;
            Some((class.to_owned(), format!("->{member}")))
        }
        Target::Type(index) => {
            let descriptor = file.type_descriptor(index)?.trim_start_matches('[');
            descriptor
                .starts_with('L')
                .then(|| (descriptor.to_owned(), String::new()))
        }
    }
}

/// The app's classes, their superclasses and the methods they define, across all DEX files
/// (Android loads the first definition of a class).
fn app_classes(files: &[&DexFile]) -> AppClasses {
    let mut app = AppClasses::default();
    for file in files {
        for class in &file.classes {
            let (Some(descriptor), Some(superclass)) =
                (file.class_descriptor(class), file.superclass(class))
            else {
                continue;
            };
            app.superclasses
                .entry(descriptor.to_owned())
                .or_insert_with(|| superclass.to_owned());
        }
        app.members.extend(
            file.defined_methods()
                .iter()
                .filter_map(|&method| file.method_signature(method)),
        );
    }
    app
}

#[cfg(test)]
mod tests {
    use super::looks_obfuscated;

    #[test]
    fn obfuscated_class_names_are_short() {
        for name in ["La;", "Lb0;", "Ll50/b;", "Lcom/x/aa;", "Lcom/Main$a;"] {
            assert!(looks_obfuscated(name), "{name}");
        }
        for name in [
            "LMain;",
            "Lcom/example/Config;",
            "Lcom/x/abc;",
            "Lcom/Main$Inner;",
            "Lcom/x/a1234;",
        ] {
            assert!(!looks_obfuscated(name), "{name}");
        }
    }
}
