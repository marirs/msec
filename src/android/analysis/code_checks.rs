//! Checks on what an app's DEX code refers to (msec origin; MobSF runs pattern rules on
//! decompiled sources instead). Each finding names the API and the app methods that call it,
//! the way Google Play's release dashboard lists them:
//!
//! - framework APIs the app refers to that Android deprecated, or removed from the public SDK;
//! - for apps targeting API 35+, the window APIs Android 15 deprecated for edge-to-edge
//!   (`setStatusBarColor` and friends no longer have an effect), and no sign that the app handles
//!   window insets at all;
//! - `BitmapFactory` decodes without `BitmapFactory.Options`, which load images at full
//!   resolution;
//! - partial wake locks acquired without a timeout;
//! - an app that signs users in on phones and tablets with no Restore Credentials or Block Store
//!   call, for Google Play's zero-tap sign-in restoration requirement (April 2027);
//! - no sign of shrinking or obfuscation (no R8 marker, few renamed classes) in an app whose DEX
//!   size makes Google Play's optimization requirement apply (more than 10 MB of DEX code, 50 MB
//!   for games, from February 2027).
//!
//! References are what code names, not data flow or reachability. A reference to a removed API
//! is not a confirmed failure: the call may sit behind a version check or in code that never
//! runs, and the platform may still have the API (removed from the SDK, kept hidden). Each
//! calling method says whether it reads the Android version, which is evidence of a guard, not
//! proof. A decode given a `null` `Options` is not found.
//!
//! [`dex_optimization`] is a measurement, not a verdict: Google Play computes its own
//! optimization, obfuscation and shrinking percentages, which a static estimate cannot
//! reproduce.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::Severity;
use super::store_checks::FormFactor;
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

/// Reads of the Android version: a method that makes one may guard its calls by release.
const VERSION_CHECKS: [&str; 4] = [
    "Landroid/os/Build$VERSION;->SDK_INT",
    "Landroid/os/Build$VERSION;->SDK_INT_FULL",
    "Landroid/os/ext/SdkExtensions;->getExtensionVersion",
    "Landroidx/core/os/BuildCompat;->isAt",
];

/// `WakeLock.acquire()` without a timeout: the lock is held until released.
const WAKE_LOCK_WITHOUT_TIMEOUT: &str = "Landroid/os/PowerManager$WakeLock;->acquire()V";

/// Calls that sign a user in, by SDK: evidence the app has sign-in, which Google Play's
/// restoration requirement applies to. A prefix of `class->member` in DEX notation. Only calls
/// from outside the API's own package count, so an SDK calling itself is not taken for the app.
const SIGN_IN_CALLS: [&str; 10] = [
    "Landroidx/credentials/CredentialManager;->getCredential",
    "Lcom/google/android/gms/auth/api/signin/GoogleSignIn;->",
    "Lcom/google/android/gms/auth/api/identity/SignInClient;->beginSignIn",
    "Lcom/google/firebase/auth/FirebaseAuth;->signIn",
    "Landroid/accounts/AccountManager;->addAccountExplicitly",
    "Lcom/facebook/login/LoginManager;->logIn",
    "Lnet/openid/appauth/AuthorizationService;->performTokenRequest",
    "Lcom/microsoft/identity/client/ISingleAccountPublicClientApplication;->signIn",
    "Lcom/auth0/android/provider/WebAuthProvider;->login",
    "Lcom/amplifyframework/auth/AuthCategory;->signIn",
];

/// References that restore sign-in on a new device: the Restore Credentials API (a restore key
/// created through Credential Manager) or Block Store.
const SIGN_IN_RESTORATION: [&str; 3] = [
    "Landroidx/credentials/CreateRestoreCredentialRequest;",
    "Lcom/google/android/gms/auth/blockstore/Blockstore;",
    "Lcom/google/android/gms/auth/blockstore/BlockstoreClient;",
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
    /// A framework API Android removed from the public SDK, referenced by at least one method
    /// that does not read the Android version. A reference, not a confirmed failure: the call
    /// fails only if it runs on a release whose platform no longer has the API.
    RemovedApi,
    /// A removed framework API referenced only by methods that also read the Android version.
    /// A heuristic label, not a lower risk: a version read in the calling method does not show
    /// that it guards this call, so the severity is the same as [`Self::RemovedApi`].
    RemovedApiVersionChecked,
    /// A window API Android 15 deprecated for edge-to-edge, in an app targeting API 35+.
    EdgeToEdgeDeprecatedApi,
    /// An app targeting API 35+ with no call that handles window insets or enables
    /// edge-to-edge: content may sit under the system bars on Android 15+.
    EdgeToEdgeNotHandled,
    /// A `BitmapFactory` decode without `BitmapFactory.Options` (no downsampling).
    BitmapWithoutDownsampling,
    /// A partial wake lock acquired without a timeout.
    WakeLockWithoutTimeout,
    /// The app calls a recognised sign-in SDK, on phones and tablets, and no recognised Restore
    /// Credentials or Block Store API: Google Play requires zero-tap sign-in restoration from
    /// April 2027. A heuristic both ways: sign-in through other SDKs is not seen, and not
    /// finding the recognised restore APIs does not establish that restoration is missing
    /// (it may be done another way). Games are out of the requirement's scope.
    SignInRestorationMissing,
    /// No R8 marker and few renamed classes, in an app whose DEX size makes Google Play's
    /// optimization requirement apply: no sign the code was shrunk or obfuscated. Not Google
    /// Play's verdict, which only Play Console shows.
    ShrinkingNotEvident,
    /// `Cipher.getInstance` with a constant transformation naming a broken algorithm (DES,
    /// 3DES, RC4, RC2, Blowfish). See [`super::security_checks`] for these and the rules below.
    CipherBrokenAlgorithm,
    /// `Cipher.getInstance` with a constant transformation naming ECB mode for a block cipher.
    CipherEcbMode,
    /// `Cipher.getInstance` with a constant `AES` and no mode: the provider's default applies.
    CipherDefaultMode,
    /// `MessageDigest.getInstance` with a constant MD2, MD4, MD5 or SHA-1.
    WeakHash,
    /// References to `java.util.Random` or `Math.random` (what the numbers are for is not
    /// established).
    InsecureRandom,
    /// A file, preferences or database opened with a constant world-readable or -writable mode,
    /// in an app targeting API 23 or lower (where Android honours it).
    WorldAccessibleFiles,
    /// The same, in an app targeting API 24 or higher: Android refuses the mode at run time.
    WorldAccessibleFilesRefused,
    /// References to shared external storage (what is written there is not established).
    ExternalStorage,
    /// `WebView.addJavascriptInterface`, in an app whose minimum API is 17 or higher (only
    /// `@JavascriptInterface` methods are exposed).
    WebViewBridge,
    /// The same, in an app that runs below API 17, where every public method of the bridged
    /// object is reachable from the page.
    WebViewBridgeReflection,
    /// `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs` with a constant
    /// `true`.
    WebViewFileUrlAccess,
    /// `setAllowFileAccess` with a constant `true`.
    WebViewFileAccess,
    /// `setAllowContentAccess` with a constant `true`.
    WebViewContentAccess,
    /// An app `WebViewClient.onReceivedSslError` override whose code calls
    /// `SslErrorHandler.proceed`.
    WebViewSslErrorProceed,
    /// `WebView.setWebContentsDebuggingEnabled` with a constant `true`.
    WebViewDebugging,
    /// Safe Browsing turned off: `setSafeBrowsingEnabled` with a constant `false`, or the
    /// manifest's `android.webkit.WebView.EnableSafeBrowsing` meta-data set to `false`.
    SafeBrowsingDisabled,
    /// References to logging APIs (`android.util.Log`, `System.out`/`System.err`); what is
    /// logged is not established.
    LoggingApi,
    /// A third-party payment SDK ships in the app, and nothing references Google Play's billing
    /// library. A lead for review: digital goods need Play's billing, physical goods and
    /// services do not. See [`super::store_leads`] for this and the rules below.
    PaymentSdkWithoutPlayBilling,
    /// The code creates accounts through a recognised SDK, and no recognised deletion call is
    /// seen. A lead: Google Play requires an in-app path to delete an account the app lets
    /// people create, which may be done server-side or through a web page.
    AccountDeletionNotSeen,
    /// The launcher activity loads a constant remote URL into a WebView, in an app with few
    /// classes of its own: possibly a repackaged website. A lead: minimum functionality is
    /// judged by review.
    WebWrapper,
}

impl CodeRule {
    /// The store-review leads ([`super::store_leads`]).
    pub const STORE_LEADS: [Self; 3] = [
        Self::PaymentSdkWithoutPlayBilling,
        Self::AccountDeletionNotSeen,
        Self::WebWrapper,
    ];

    /// The security rules on cryptography, storage, WebViews and logging
    /// ([`super::security_checks`]).
    pub const SECURITY: [Self; 17] = [
        Self::CipherBrokenAlgorithm,
        Self::CipherEcbMode,
        Self::CipherDefaultMode,
        Self::WeakHash,
        Self::InsecureRandom,
        Self::WorldAccessibleFiles,
        Self::WorldAccessibleFilesRefused,
        Self::ExternalStorage,
        Self::WebViewBridge,
        Self::WebViewBridgeReflection,
        Self::WebViewFileUrlAccess,
        Self::WebViewFileAccess,
        Self::WebViewContentAccess,
        Self::WebViewSslErrorProceed,
        Self::WebViewDebugging,
        Self::SafeBrowsingDisabled,
        Self::LoggingApi,
    ];

    /// Engine key.
    pub fn key(self) -> &'static str {
        match self {
            Self::DeprecatedApi => "msec_code_deprecated_api",
            Self::RemovedApi => "msec_code_removed_api",
            Self::RemovedApiVersionChecked => "msec_code_removed_api_version_checked",
            Self::EdgeToEdgeDeprecatedApi => "msec_store_edge_to_edge_deprecated_api",
            Self::EdgeToEdgeNotHandled => "msec_store_edge_to_edge_not_handled",
            Self::BitmapWithoutDownsampling => "msec_store_bitmap_without_downsampling",
            Self::WakeLockWithoutTimeout => "msec_store_wake_lock_without_timeout",
            Self::SignInRestorationMissing => "msec_store_sign_in_restoration_missing",
            Self::ShrinkingNotEvident => "msec_store_dex_shrinking_not_evident",
            Self::PaymentSdkWithoutPlayBilling => "msec_store_payment_sdk_without_play_billing",
            Self::AccountDeletionNotSeen => "msec_store_account_deletion_not_seen",
            Self::WebWrapper => "msec_store_web_wrapper",
            Self::CipherBrokenAlgorithm => "msec_code_cipher_broken_algorithm",
            Self::CipherEcbMode => "msec_code_cipher_ecb_mode",
            Self::CipherDefaultMode => "msec_code_cipher_default_mode",
            Self::WeakHash => "msec_code_weak_hash",
            Self::InsecureRandom => "msec_code_insecure_random",
            Self::WorldAccessibleFiles => "msec_code_world_accessible_files",
            Self::WorldAccessibleFilesRefused => "msec_code_world_accessible_files_refused",
            Self::ExternalStorage => "msec_code_external_storage",
            Self::WebViewBridge => "msec_code_webview_bridge",
            Self::WebViewBridgeReflection => "msec_code_webview_bridge_reflection",
            Self::WebViewFileUrlAccess => "msec_code_webview_file_url_access",
            Self::WebViewFileAccess => "msec_code_webview_file_access",
            Self::WebViewContentAccess => "msec_code_webview_content_access",
            Self::WebViewSslErrorProceed => "msec_code_webview_ssl_error_proceed",
            Self::WebViewDebugging => "msec_code_webview_debugging",
            Self::SafeBrowsingDisabled => "msec_code_safe_browsing_disabled",
            Self::LoggingApi => "msec_code_logging_api",
        }
    }

    /// Severity on MobSF's scale.
    pub fn severity(self) -> Severity {
        match self {
            Self::RemovedApi | Self::RemovedApiVersionChecked | Self::ShrinkingNotEvident => {
                Severity::Warning
            }
            Self::CipherBrokenAlgorithm
            | Self::CipherEcbMode
            | Self::WorldAccessibleFiles
            | Self::WebViewBridgeReflection
            | Self::WebViewFileUrlAccess
            | Self::WebViewSslErrorProceed => Severity::High,
            Self::CipherDefaultMode
            | Self::WeakHash
            | Self::InsecureRandom
            | Self::WorldAccessibleFilesRefused
            | Self::WebViewBridge
            | Self::WebViewFileAccess
            | Self::WebViewDebugging
            | Self::SafeBrowsingDisabled => Severity::Warning,
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
    /// Calling methods, sorted, up to 20.
    pub callers: Vec<Caller>,
    /// All calling methods, listed or not.
    pub caller_count: usize,
    /// Calling methods that read the Android version, listed or not.
    pub version_checked_callers: usize,
    /// What it means, in words.
    pub detail: String,
    /// What shows it: a reference to the API, a constant argument at the call site, an
    /// override that calls it, or the manifest.
    pub evidence: CodeEvidence,
    /// The constant argument, when that is the evidence (`AES/ECB/PKCS5Padding`, `true`).
    pub argument: Option<String>,
}

/// What a code finding rests on. None of these is data flow or reachability: a reference shows
/// the code names the API; a constant argument shows the value the code passes at that call
/// (set on the only path into it, within the calling method); an override shows a method of
/// the app's subclass calls it; the manifest shows a declared setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeEvidence {
    /// The code refers to the API.
    Reference,
    /// The code passes a constant argument at the call site.
    ConstantArgument,
    /// An override in an app subclass calls the API.
    Override,
    /// The manifest declares the setting.
    Manifest,
}

/// A method that refers to the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The method in DEX notation.
    pub method: String,
    /// It also reads the Android version (`Build.VERSION.SDK_INT` and the like), so its call may
    /// be guarded by release. Evidence of a guard, not proof: the check may guard something
    /// else, and a guard in the method's own callers is not seen.
    pub checks_version: bool,
}

/// How much of an app's code looks shrunk and obfuscated: an estimate from the build's markers
/// and class names, not Google Play's measurement.
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

    /// The build shows shrinking or obfuscation: R8 ran (its marker is present), or at least
    /// Google Play's minimum share of classes was renamed by some obfuscator. Evidence about the
    /// build, not Google Play's verdict: Play measures optimization, obfuscation and shrinking
    /// separately, and its percentages are in Play Console.
    pub fn shrinking_evident(&self) -> bool {
        self.r8 || self.obfuscated_percent() >= PLAY_DEX_MINIMUM_PERCENT
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
pub fn is_game(document: Option<&XmlDocument>) -> bool {
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
            (Some(removed), _) => removed_api(api, removed, callers, &calls.version_checking),
            (None, Some(deprecated)) => (
                CodeRule::DeprecatedApi,
                format!("deprecated in API {deprecated}"),
            ),
            (None, None) => continue,
        };
        findings.push(calls.finding(rule, Some(api), callers, detail));
    }
    if target_sdk >= EDGE_TO_EDGE_FROM {
        for api in EDGE_TO_EDGE_DEPRECATED {
            if let Some(callers) = calls.direct.get(api) {
                let detail = "deprecated in API 35; has no effect on Android 15+, where apps \
                              targeting API 35 are edge-to-edge"
                    .to_owned();
                findings.push(calls.finding(
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
            findings.push(app_wide(
                CodeRule::EdgeToEdgeNotHandled,
                format!(
                    "targets API {target_sdk}, so it is edge-to-edge on Android 15+, and no code \
                     enables edge-to-edge or handles window insets"
                ),
            ));
        }
    }
    for api in BITMAP_WITHOUT_OPTIONS {
        if let Some(callers) = calls.direct.get(api) {
            let detail =
                "decodes at full resolution: no BitmapFactory.Options, so no inSampleSize \
                          downsampling"
                    .to_owned();
            findings.push(calls.finding(
                CodeRule::BitmapWithoutDownsampling,
                Some(api),
                callers,
                detail,
            ));
        }
    }
    if let Some(callers) = calls.direct.get(WAKE_LOCK_WITHOUT_TIMEOUT) {
        let detail = "acquired without a timeout: the wake lock stays held until the app \
                      releases it, and one never released keeps the device awake"
            .to_owned();
        findings.push(calls.finding(
            CodeRule::WakeLockWithoutTimeout,
            Some(WAKE_LOCK_WITHOUT_TIMEOUT),
            callers,
            detail,
        ));
    }
    let restoration_applies =
        FormFactor::of(manifest) == FormFactor::PhoneTablet && !is_game(manifest_document);
    if restoration_applies && let Some((api, callers)) = sign_in_without_restoration(&calls.direct)
    {
        // The sign-in API is the finding's `api`, so the detail does not repeat it.
        let detail = "calls a recognised sign-in SDK, and no recognised Restore Credentials or \
                      Block Store API (heuristic: restoration done another way is not seen, so \
                      this does not establish that it is missing). From April 2027 Google Play \
                      requires apps with sign-in to restore it on a new device without user \
                      action (phones and tablets); Block Store integrations in production by 30 \
                      September 2026 also count"
            .to_owned();
        findings.push(calls.finding(
            CodeRule::SignInRestorationMissing,
            Some(api),
            &callers,
            detail,
        ));
    }
    let optimization = dex_optimization(dex_files, manifest_document);
    if optimization.play_requirement_applies() && !optimization.shrinking_evident() {
        findings.push(app_wide(
            CodeRule::ShrinkingNotEvident,
            format!(
                "no R8 marker in any DEX file, and about {}% of {} class names look obfuscated \
                 (estimated from class names): no sign the code was shrunk or obfuscated. Google \
                 Play requires at least {}% optimization, obfuscation and shrinking for apps with \
                 more than {} MB of DEX code ({} MB here) from February 2027, and measures them \
                 itself",
                optimization.obfuscated_percent(),
                optimization.classes,
                PLAY_DEX_MINIMUM_PERCENT,
                optimization.play_threshold_bytes / (1024 * 1024),
                optimization.dex_bytes / (1024 * 1024),
            ),
        ));
    }
    findings.extend(super::security_checks::analyse_security(
        dex_files, manifest,
    ));
    findings.extend(super::store_leads::analyse_store_leads(
        dex_files,
        manifest,
        &calls.direct,
    ));
    findings.sort_by(|left, right| {
        (left.rule, &left.api, &left.argument).cmp(&(right.rule, &right.api, &right.argument))
    });
    findings
}

/// A removed API: which rule, by whether every calling method reads the Android version, and
/// what it means. Worded as a reference, never as a failure: version checks, code that never
/// runs and a platform that kept the API hidden all prevent one, and none is decided here.
fn removed_api(
    api: &str,
    removed: u16,
    callers: &BTreeSet<String>,
    version_checking: &HashSet<String>,
) -> (CodeRule, String) {
    let checked = callers
        .iter()
        .filter(|caller| version_checking.contains(*caller))
        .count();
    let error = match api.split_once("->") {
        Some((_, member)) if member.contains('(') => "NoSuchMethodError",
        Some(_) => "NoSuchFieldError",
        None => "NoClassDefFoundError",
    };
    let consequence = format!(
        "removed from the public SDK in API {removed}. A call that runs on API {removed} or later \
         fails with {error} if that release's platform no longer has the API; a version check, \
         or code that never runs, prevents that, and reachability is not analysed"
    );
    // Heuristic: a version read elsewhere in the calling method may guard something else.
    const HEURISTIC: &str = "a heuristic: reading the version in the same method does not show \
                             that it guards this call";
    if checked == callers.len() {
        let detail = format!(
            "{consequence}. Every referencing method also reads the Android version ({HEURISTIC})"
        );
        (CodeRule::RemovedApiVersionChecked, detail)
    } else {
        let detail = format!(
            "{consequence}. {} of {} referencing methods also read the Android version \
             ({HEURISTIC})",
            checked,
            callers.len()
        );
        (CodeRule::RemovedApi, detail)
    }
}

/// The first sign-in call made from outside the signing-in SDK's own package, with those
/// callers, when nothing references the Restore Credentials API or Block Store.
fn sign_in_without_restoration(
    direct: &HashMap<String, BTreeSet<String>>,
) -> Option<(&str, BTreeSet<String>)> {
    let restores = direct.keys().any(|api| {
        SIGN_IN_RESTORATION
            .iter()
            .any(|prefix| api.starts_with(prefix))
    });
    if restores {
        return None;
    }
    let mut sign_ins: Vec<(&str, BTreeSet<String>)> = direct
        .iter()
        .filter(|(api, _)| SIGN_IN_CALLS.iter().any(|prefix| api.starts_with(prefix)))
        .filter_map(|(api, callers)| {
            let package = api
                .split_once("->")
                .map_or(api.as_str(), |(class, _)| class);
            let package = &package[..package.rfind('/').unwrap_or(0) + 1];
            let outside: BTreeSet<String> = callers
                .iter()
                .filter(|caller| !caller.starts_with(package))
                .cloned()
                .collect();
            (!outside.is_empty()).then_some((api.as_str(), outside))
        })
        .collect();
    sign_ins.sort_by(|left, right| left.0.cmp(right.0));
    sign_ins.into_iter().next()
}

/// A finding about the app as a whole, not an API.
fn app_wide(rule: CodeRule, detail: String) -> CodeFinding {
    CodeFinding {
        rule,
        api: None,
        callers: Vec::new(),
        caller_count: 0,
        version_checked_callers: 0,
        detail,
        evidence: CodeEvidence::Reference,
        argument: None,
    }
}

/// Who calls what, across all DEX files: references as written (`direct`, by signature), the
/// deprecated or removed framework APIs they reach (`framework`), and the methods that read the
/// Android version (`version_checking`).
#[derive(Default)]
struct ReferenceIndex {
    direct: HashMap<String, BTreeSet<String>>,
    framework: BTreeMap<String, (ApiChange, BTreeSet<String>)>,
    version_checking: HashSet<String>,
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
                let target = format!("{class}{member}");
                if VERSION_CHECKS.iter().any(|check| target.starts_with(check)) {
                    index.version_checking.insert(caller.clone());
                }
                index
                    .direct
                    .entry(target)
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

    /// A finding about `api`, naming its callers and whether each reads the Android version.
    fn finding(
        &self,
        rule: CodeRule,
        api: Option<&str>,
        callers: &BTreeSet<String>,
        detail: String,
    ) -> CodeFinding {
        let checks_version = |method: &String| self.version_checking.contains(method);
        CodeFinding {
            rule,
            api: api.map(str::to_owned),
            callers: callers
                .iter()
                .take(MAX_CALLERS)
                .map(|method| Caller {
                    method: method.clone(),
                    checks_version: checks_version(method),
                })
                .collect(),
            caller_count: callers.len(),
            version_checked_callers: callers
                .iter()
                .filter(|method| checks_version(method))
                .count(),
            detail,
            evidence: CodeEvidence::Reference,
            argument: None,
        }
    }
}

/// `(class, member)` of a reference: `->name(params)return` for methods, `->name` for fields,
/// empty for types (arrays reduced to their element class).
pub(super) fn target_parts(file: &DexFile, target: Target) -> Option<(String, String)> {
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
pub(super) fn app_classes(files: &[&DexFile]) -> AppClasses {
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
    use std::collections::{BTreeSet, HashMap};

    use super::{looks_obfuscated, sign_in_without_restoration};

    /// Sign-in counts from app code, not from the SDK calling itself, and a Restore Credentials
    /// or Block Store reference anywhere satisfies the requirement.
    #[test]
    fn sign_in_needs_a_restoration_call() {
        let calls = |entries: &[(&str, &str)]| {
            let mut direct: HashMap<String, BTreeSet<String>> = HashMap::new();
            for (api, caller) in entries {
                direct
                    .entry((*api).to_owned())
                    .or_default()
                    .insert((*caller).to_owned());
            }
            direct
        };
        let sign_in = "Lcom/google/firebase/auth/FirebaseAuth;->signInWithCredential(La;)Lb;";
        let app = "Lcom/example/Login;->submit()V";
        let sdk = "Lcom/google/firebase/auth/internal/Helper;->run()V";
        let from_app = calls(&[(sign_in, app), (sign_in, sdk)]);
        let (api, callers) = sign_in_without_restoration(&from_app).expect("sign-in from app code");
        assert_eq!(api, sign_in);
        assert_eq!(callers, BTreeSet::from([app.to_owned()]));
        assert!(sign_in_without_restoration(&calls(&[(sign_in, sdk)])).is_none());
        let restore =
            "Landroidx/credentials/CreateRestoreCredentialRequest;-><init>(Ljava/lang/String;Z)V";
        assert!(sign_in_without_restoration(&calls(&[(sign_in, app), (restore, app)])).is_none());
        let block_store = "Lcom/google/android/gms/auth/blockstore/Blockstore;";
        assert!(
            sign_in_without_restoration(&calls(&[(sign_in, app), (block_store, app)])).is_none()
        );
    }

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
