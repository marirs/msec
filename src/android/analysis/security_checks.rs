//! Security checks on what an app's DEX code calls, for cryptography, storage, WebViews and
//! logging (msec origin; MobSF runs pattern rules on decompiled sources). Each finding says
//! what it rests on ([`CodeEvidence`]):
//!
//! - a constant argument at the call site, which shows the value the code passes there (the
//!   transformation `AES/ECB/PKCS5Padding`, the mode `MODE_WORLD_READABLE`, `true`): set on the
//!   only path into the call within the calling method ([`crate::android::dex::Constant`]);
//! - a reference, which shows the code names the API and nothing about how it is used
//!   (`java.util.Random`, external storage, logging): these rules are heuristics;
//! - an override: an app `WebViewClient.onReceivedSslError` whose code calls `proceed`;
//! - the manifest: Safe Browsing turned off by meta-data.
//!
//! None of these is a proven vulnerability: whether the call runs, and what the data is, are
//! not established. Calls whose argument is not a constant at the call site (a parameter, a
//! field, a value merged from two branches, built at run time) are not reported by the
//! constant-argument rules, so those rules can miss what they look for.
//!
//! Calls are matched by the framework method they reach: a call through an app subclass
//! (`MainActivity.openFileOutput`) resolves to the framework class that declares the member,
//! as in [`crate::android::api::resolve`]. Constructors are matched on their own class only,
//! so `new SecureRandom()` is never taken for `new Random()`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::code_checks::{Caller, CodeEvidence, CodeFinding, CodeRule, app_classes, target_parts};
use crate::android::api::{AppClasses, framework_superclass};
use crate::android::dex::{Constant, DexEntry, DexFile, Target};
use crate::android::manifest::Manifest;

/// Calling methods listed per finding; the rest are counted.
const MAX_CALLERS: usize = 20;
/// Superclass chains followed at most this far.
const MAX_HIERARCHY_DEPTH: usize = 64;

/// `Cipher.getInstance` overloads; the transformation is argument slot 0 (static).
const CIPHER_GET_INSTANCE: [&str; 3] = [
    "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;",
    "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/Cipher;",
    "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;Ljava/security/Provider;)Ljavax/crypto/Cipher;",
];
/// `MessageDigest.getInstance` overloads; the algorithm is slot 0.
const DIGEST_GET_INSTANCE: [&str; 3] = [
    "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;",
    "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljava/security/MessageDigest;",
    "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;Ljava/security/Provider;)Ljava/security/MessageDigest;",
];
/// Block or stream ciphers that are broken: DES (56-bit keys), 3DES (64-bit blocks), RC4, RC2,
/// Blowfish (64-bit blocks). Upper-cased algorithm names as `Cipher` accepts them.
const BROKEN_ALGORITHMS: [&str; 8] = [
    "DES",
    "DESEDE",
    "TRIPLEDES",
    "3DES",
    "RC4",
    "ARCFOUR",
    "RC2",
    "BLOWFISH",
];
/// Algorithms whose `ECB` names a block mode (for RSA, `ECB` is a naming convention without
/// chaining, and is not reported).
const BLOCK_CIPHERS: [&str; 9] = [
    "AES",
    "DES",
    "DESEDE",
    "TRIPLEDES",
    "3DES",
    "RC2",
    "BLOWFISH",
    "CAMELLIA",
    "SEED",
];
/// Hash algorithms with practical collisions, upper-cased.
const WEAK_HASHES: [&str; 5] = ["MD2", "MD4", "MD5", "SHA-1", "SHA1"];
/// `java.util.Random` and `Math.random`: predictable sequences.
const INSECURE_RANDOM: [&str; 3] = [
    "Ljava/util/Random;-><init>()V",
    "Ljava/util/Random;-><init>(J)V",
    "Ljava/lang/Math;->random()D",
];
/// `Context` methods taking a file mode, with the mode's argument slot (slot 0 is `this`).
const MODE_TAKING: [&str; 5] = [
    "Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;",
    "Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
    "Landroid/content/Context;->openOrCreateDatabase(Ljava/lang/String;ILandroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;",
    "Landroid/content/Context;->openOrCreateDatabase(Ljava/lang/String;ILandroid/database/sqlite/SQLiteDatabase$CursorFactory;Landroid/database/DatabaseErrorHandler;)Landroid/database/sqlite/SQLiteDatabase;",
    "Landroid/content/Context;->getDir(Ljava/lang/String;I)Ljava/io/File;",
];
const MODE_SLOT: u8 = 2;
/// `Context.MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE`.
const WORLD_READABLE: i32 = 1;
const WORLD_WRITEABLE: i32 = 2;
/// Android 7.0 (API 24) throws `SecurityException` for these modes in apps targeting it.
const WORLD_MODES_REFUSED_FROM: u32 = 24;
/// Shared external storage.
const EXTERNAL_STORAGE: [&str; 7] = [
    "Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;",
    "Landroid/os/Environment;->getExternalStoragePublicDirectory(Ljava/lang/String;)Ljava/io/File;",
    "Landroid/content/Context;->getExternalFilesDir(Ljava/lang/String;)Ljava/io/File;",
    "Landroid/content/Context;->getExternalFilesDirs(Ljava/lang/String;)[Ljava/io/File;",
    "Landroid/content/Context;->getExternalCacheDir()Ljava/io/File;",
    "Landroid/content/Context;->getExternalCacheDirs()[Ljava/io/File;",
    "Landroid/content/Context;->getExternalMediaDirs()[Ljava/io/File;",
];
const ADD_JAVASCRIPT_INTERFACE: &str =
    "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V";
/// Below API 17 every public method of a bridged object, `getClass` included, is reachable
/// (CVE-2012-6636); from API 17 only methods annotated `@JavascriptInterface`.
const BRIDGE_ANNOTATION_FROM: u32 = 17;
/// `WebSettings` switches with their meaning when given `true`, slot 1 (after `this`).
const FILE_URL_ACCESS: [&str; 2] = [
    "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V",
    "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V",
];
const FILE_ACCESS: &str = "Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V";
const CONTENT_ACCESS: &str = "Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V";
const SAFE_BROWSING: &str = "Landroid/webkit/WebSettings;->setSafeBrowsingEnabled(Z)V";
const SETTING_SLOT: u8 = 1;
/// Static: the flag is slot 0.
const WEB_CONTENTS_DEBUGGING: &str = "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V";
const WEB_VIEW_CLIENT: &str = "Landroid/webkit/WebViewClient;";
const ON_RECEIVED_SSL_ERROR: &str = "->onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V";
const SSL_PROCEED: &str = "Landroid/webkit/SslErrorHandler;->proceed()V";
const SAFE_BROWSING_META_DATA: &str = "android.webkit.WebView.EnableSafeBrowsing";
/// `android.util.Log` methods, by name prefix of the member.
const LOG_METHODS: [&str; 7] = [
    "Landroid/util/Log;->v(",
    "Landroid/util/Log;->d(",
    "Landroid/util/Log;->i(",
    "Landroid/util/Log;->w(",
    "Landroid/util/Log;->e(",
    "Landroid/util/Log;->wtf(",
    "Landroid/util/Log;->println(",
];
/// `System.out` and `System.err`, and what prints to them.
const STANDARD_STREAMS: [&str; 2] = ["Ljava/lang/System;->out", "Ljava/lang/System;->err"];
const PRINT_STREAM_PRINT: [&str; 2] = [
    "Ljava/io/PrintStream;->print(",
    "Ljava/io/PrintStream;->println(",
];

/// The security findings on an app's code; `manifest` gives the SDK levels the meaning of some
/// calls depends on, and the meta-data.
pub fn analyse_security(dex_files: &[DexEntry], manifest: &Manifest) -> Vec<CodeFinding> {
    let min_sdk = manifest.min_sdk().unwrap_or(1);
    let target_sdk = manifest.target_sdk().unwrap_or(min_sdk);
    let index = CallIndex::of(dex_files);
    let mut findings = Vec::new();
    cryptography(&index, &mut findings);
    storage(&index, target_sdk, &mut findings);
    web_views(&index, min_sdk, manifest, &mut findings);
    logging(&index, &mut findings);
    findings
}

/// What the code calls, by the framework member each call reaches.
#[derive(Default)]
struct CallIndex {
    /// Framework member (DEX notation) to the methods that refer to it.
    references: HashMap<String, BTreeSet<String>>,
    /// (framework member, slot, constant as text) to the methods that pass it.
    constants: BTreeMap<(String, u8, ConstantText), BTreeSet<String>>,
    /// Field references (`Lclass;->name`) to the methods that read them.
    fields: HashMap<String, BTreeSet<String>>,
    /// App methods overriding a framework member (`Lframework;->name(...)`), each with what
    /// its own code refers to.
    overrides: HashMap<String, Vec<(String, BTreeSet<String>)>>,
}

/// A constant as text: a string's characters, or an integer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ConstantText {
    Int(i32),
    String(String),
}

/// The string constants passed to a framework `member` (DEX notation, resolved through app
/// subclasses) at argument `slot`, each with the methods that pass it.
pub(super) fn string_arguments(
    dex_files: &[DexEntry],
    member: &str,
    slot: u8,
) -> BTreeMap<String, BTreeSet<String>> {
    CallIndex::of(dex_files)
        .constants
        .into_iter()
        .filter_map(|((reached, at, value), callers)| match value {
            ConstantText::String(text) if reached == member && at == slot => Some((text, callers)),
            _ => None,
        })
        .collect()
}

impl CallIndex {
    fn of(dex_files: &[DexEntry]) -> Self {
        let files: Vec<&DexFile> = dex_files
            .iter()
            .flat_map(|entry| &entry.container.files)
            .collect();
        let app = app_classes(&files);
        let mut index = Self::default();
        let mut resolved: HashMap<(String, String), Vec<String>> = HashMap::new();
        let mut reach = |class: &str, member: &str| -> Vec<String> {
            resolved
                .entry((class.to_owned(), member.to_owned()))
                .or_insert_with(|| framework_members(class, member, &app))
                .clone()
        };
        for file in &files {
            let mut own_references: HashMap<u32, BTreeSet<String>> = HashMap::new();
            for reference in file.references() {
                let Some((class, member)) = target_parts(file, reference.target) else {
                    continue;
                };
                let Some(caller) = file.method_signature(reference.caller) else {
                    continue;
                };
                match reference.target {
                    Target::Method(_) => {
                        for reached in reach(&class, &member) {
                            index
                                .references
                                .entry(reached.clone())
                                .or_default()
                                .insert(caller.clone());
                            own_references
                                .entry(reference.caller)
                                .or_default()
                                .insert(reached);
                        }
                    }
                    Target::Field(_) => {
                        index
                            .fields
                            .entry(format!("{class}{member}"))
                            .or_default()
                            .insert(caller);
                    }
                    Target::Type(_) => {}
                }
            }
            for argument in file.constant_arguments() {
                let Some((class, member)) = target_parts(file, Target::Method(argument.callee))
                else {
                    continue;
                };
                let Some(caller) = file.method_signature(argument.caller) else {
                    continue;
                };
                let value = match argument.value {
                    Constant::Int(value) => ConstantText::Int(value),
                    Constant::String(string) => match file.string(string) {
                        Some(text) => ConstantText::String(text.to_owned()),
                        None => continue,
                    },
                };
                for reached in reach(&class, &member) {
                    index
                        .constants
                        .entry((reached, argument.slot, value.clone()))
                        .or_default()
                        .insert(caller.clone());
                }
            }
            // Overrides: methods an app class defines whose member a framework superclass has.
            for &method in file.defined_methods() {
                let Some(signature) = file.method_signature(method) else {
                    continue;
                };
                let Some((class, member)) = signature.split_once("->") else {
                    continue;
                };
                let Some(superclass) = app.superclasses.get(class) else {
                    continue;
                };
                let member = format!("->{member}");
                for overridden in framework_ancestors(superclass, &app) {
                    index
                        .overrides
                        .entry(format!("{overridden}{member}"))
                        .or_default()
                        .push((
                            signature.clone(),
                            own_references.get(&method).cloned().unwrap_or_default(),
                        ));
                }
            }
        }
        index
    }

    /// The methods that pass `value` as argument `slot` of any of `apis`, by API.
    fn constant_callers<'a>(
        &'a self,
        apis: &'a [&str],
        slot: u8,
        matches: impl Fn(&ConstantText) -> bool + 'a,
    ) -> impl Iterator<Item = (&'a str, &'a ConstantText, &'a BTreeSet<String>)> + 'a {
        self.constants
            .iter()
            .filter(move |((api, at, value), _)| {
                *at == slot && apis.contains(&api.as_str()) && matches(value)
            })
            .map(|((api, _, value), callers)| (api.as_str(), value, callers))
    }

    /// The methods that refer to any of `apis` (exact members, or prefixes ending in `(`),
    /// by API.
    fn reference_callers<'a>(
        &'a self,
        apis: &'a [&str],
    ) -> impl Iterator<Item = (&'a str, &'a BTreeSet<String>)> + 'a {
        let mut found: Vec<(&str, &BTreeSet<String>)> = self
            .references
            .iter()
            .filter(|(api, _)| {
                apis.iter().any(|wanted| {
                    if wanted.ends_with('(') {
                        api.starts_with(wanted)
                    } else {
                        api.as_str() == *wanted
                    }
                })
            })
            .map(|(api, callers)| (api.as_str(), callers))
            .collect();
        found.sort();
        found.into_iter()
    }
}

/// The framework members a reference to `class` + `member` reaches: up the app's own classes
/// (stopping where an app class defines the member itself), then the framework's. Every
/// framework class on the way is a candidate, since which one declares the member is not
/// recorded; callers match against the members they look for. Constructors and types are
/// their own class only.
fn framework_members(class: &str, member: &str, app: &AppClasses) -> Vec<String> {
    if member.starts_with("-><init>") || member.is_empty() {
        return vec![format!("{class}{member}")];
    }
    let mut found = Vec::new();
    let mut current = class.to_owned();
    for _ in 0..MAX_HIERARCHY_DEPTH {
        if let Some(superclass) = app.superclasses.get(&current) {
            if app.members.contains(&format!("{current}{member}")) {
                return found;
            }
            current = superclass.clone();
            continue;
        }
        found.push(format!("{current}{member}"));
        match framework_superclass(&current) {
            Some(superclass) => current = superclass.to_owned(),
            None => break,
        }
    }
    found
}

/// The framework classes above an app class's framework superclass, itself included.
fn framework_ancestors(superclass: &str, app: &AppClasses) -> Vec<String> {
    let mut found = Vec::new();
    let mut current = superclass.to_owned();
    for _ in 0..MAX_HIERARCHY_DEPTH {
        if let Some(next) = app.superclasses.get(&current) {
            current = next.clone();
            continue;
        }
        found.push(current.clone());
        match framework_superclass(&current) {
            Some(next) => current = next.to_owned(),
            None => break,
        }
    }
    found
}

fn finding(
    rule: CodeRule,
    api: &str,
    callers: &BTreeSet<String>,
    evidence: CodeEvidence,
    argument: Option<String>,
    detail: String,
) -> CodeFinding {
    CodeFinding {
        rule,
        api: Some(api.to_owned()),
        callers: callers
            .iter()
            .take(MAX_CALLERS)
            .map(|method| Caller {
                method: method.clone(),
                checks_version: false,
            })
            .collect(),
        caller_count: callers.len(),
        version_checked_callers: 0,
        detail,
        evidence,
        argument,
    }
}

/// `AES_256/GCM/NoPadding` as (`AES`, `GCM`): the algorithm without a key-size suffix, and the
/// mode, upper-cased.
fn transformation_parts(transformation: &str) -> (String, Option<String>) {
    let mut parts = transformation.split('/');
    let algorithm = parts.next().unwrap_or_default().to_ascii_uppercase();
    let algorithm = algorithm
        .split_once('_')
        .map_or(algorithm.clone(), |(name, _)| name.to_owned());
    let mode = parts.next().map(str::to_ascii_uppercase);
    (algorithm, mode)
}

fn cryptography(index: &CallIndex, findings: &mut Vec<CodeFinding>) {
    for (api, value, callers) in index.constant_callers(&CIPHER_GET_INSTANCE, 0, |_| true) {
        let ConstantText::String(transformation) = value else {
            continue;
        };
        let (algorithm, mode) = transformation_parts(transformation);
        let found = if BROKEN_ALGORITHMS.contains(&algorithm.as_str()) {
            Some((
                CodeRule::CipherBrokenAlgorithm,
                format!("requests the {algorithm} cipher, which is broken"),
            ))
        } else if mode.as_deref() == Some("ECB") && BLOCK_CIPHERS.contains(&algorithm.as_str()) {
            Some((
                CodeRule::CipherEcbMode,
                format!(
                    "requests {algorithm} in ECB mode, which encrypts equal blocks to equal \
                     ciphertext"
                ),
            ))
        } else if mode.is_none() && algorithm == "AES" {
            Some((
                CodeRule::CipherDefaultMode,
                "requests AES without a mode, so the provider chooses one (ECB with PKCS#5 \
                 padding in Android's providers)"
                    .to_owned(),
            ))
        } else {
            None
        };
        if let Some((rule, detail)) = found {
            findings.push(finding(
                rule,
                api,
                callers,
                CodeEvidence::ConstantArgument,
                Some(transformation.clone()),
                format!("{detail}: Cipher.getInstance(\"{transformation}\") at the call site"),
            ));
        }
    }
    for (api, value, callers) in index.constant_callers(&DIGEST_GET_INSTANCE, 0, |_| true) {
        let ConstantText::String(algorithm) = value else {
            continue;
        };
        if WEAK_HASHES.contains(&algorithm.to_ascii_uppercase().as_str()) {
            findings.push(finding(
                CodeRule::WeakHash,
                api,
                callers,
                CodeEvidence::ConstantArgument,
                Some(algorithm.clone()),
                format!(
                    "requests the {algorithm} hash, which has practical collisions: \
                     MessageDigest.getInstance(\"{algorithm}\") at the call site; whether it \
                     protects anything (a signature, a password) is not established"
                ),
            ));
        }
    }
    for (api, callers) in index.reference_callers(&INSECURE_RANDOM) {
        findings.push(finding(
            CodeRule::InsecureRandom,
            api,
            callers,
            CodeEvidence::Reference,
            None,
            "uses a predictable random number generator; whether its numbers serve security \
             (tokens, keys, nonces) is not established"
                .to_owned(),
        ));
    }
}

fn storage(index: &CallIndex, target_sdk: u32, findings: &mut Vec<CodeFinding>) {
    let world = |value: &ConstantText| matches!(value, ConstantText::Int(mode) if mode & (WORLD_READABLE | WORLD_WRITEABLE) != 0);
    for (api, value, callers) in index.constant_callers(&MODE_TAKING, MODE_SLOT, world) {
        let ConstantText::Int(mode) = value else {
            continue;
        };
        let named = match (mode & WORLD_READABLE != 0, mode & WORLD_WRITEABLE != 0) {
            (true, true) => "MODE_WORLD_READABLE | MODE_WORLD_WRITEABLE",
            (true, false) => "MODE_WORLD_READABLE",
            _ => "MODE_WORLD_WRITEABLE",
        };
        let (rule, consequence) = if target_sdk >= WORLD_MODES_REFUSED_FROM {
            (
                CodeRule::WorldAccessibleFilesRefused,
                format!(
                    "the app targets API {target_sdk}, so Android 7.0 and later refuse the mode \
                     with a SecurityException"
                ),
            )
        } else {
            (
                CodeRule::WorldAccessibleFiles,
                format!(
                    "the app targets API {target_sdk}, so Android grants it: other apps may read \
                     or write the file"
                ),
            )
        };
        findings.push(finding(
            rule,
            api,
            callers,
            CodeEvidence::ConstantArgument,
            Some(named.to_owned()),
            format!("opens with {named} at the call site; {consequence}"),
        ));
    }
    for (api, callers) in index.reference_callers(&EXTERNAL_STORAGE) {
        findings.push(finding(
            CodeRule::ExternalStorage,
            api,
            callers,
            CodeEvidence::Reference,
            None,
            "refers to shared external storage, which other apps with storage access can read; \
             what the app stores there is not established"
                .to_owned(),
        ));
    }
}

fn web_views(
    index: &CallIndex,
    min_sdk: u32,
    manifest: &Manifest,
    findings: &mut Vec<CodeFinding>,
) {
    for (api, callers) in index.reference_callers(&[ADD_JAVASCRIPT_INTERFACE]) {
        let (rule, detail) = if min_sdk < BRIDGE_ANNOTATION_FROM {
            (
                CodeRule::WebViewBridgeReflection,
                format!(
                    "exposes a Java object to the WebView's JavaScript, and the app runs from API \
                     {min_sdk}: below API 17 every public method of the object is reachable from \
                     the page, including through reflection (CVE-2012-6636)"
                ),
            )
        } else {
            (
                CodeRule::WebViewBridge,
                "exposes a Java object's @JavascriptInterface methods to the WebView's \
                 JavaScript: any page the WebView loads can call them"
                    .to_owned(),
            )
        };
        findings.push(finding(
            rule,
            api,
            callers,
            CodeEvidence::Reference,
            None,
            detail,
        ));
    }
    let is_true = |value: &ConstantText| *value == ConstantText::Int(1);
    let is_false = |value: &ConstantText| *value == ConstantText::Int(0);
    for (api, _, callers) in index.constant_callers(&FILE_URL_ACCESS, SETTING_SLOT, is_true) {
        findings.push(finding(
            CodeRule::WebViewFileUrlAccess,
            api,
            callers,
            CodeEvidence::ConstantArgument,
            Some("true".to_owned()),
            "lets JavaScript in file: pages read other files (or any origin): true at the call \
             site"
                .to_owned(),
        ));
    }
    for (rule, setting, detail) in [
        (
            CodeRule::WebViewFileAccess,
            FILE_ACCESS,
            "lets the WebView load file: URLs from the device: true at the call site",
        ),
        (
            CodeRule::WebViewContentAccess,
            CONTENT_ACCESS,
            "lets the WebView load content: URLs from content providers: true at the call site",
        ),
    ] {
        for (api, _, callers) in index.constant_callers(&[setting], SETTING_SLOT, is_true) {
            findings.push(finding(
                rule,
                api,
                callers,
                CodeEvidence::ConstantArgument,
                Some("true".to_owned()),
                detail.to_owned(),
            ));
        }
    }
    for (api, _, callers) in index.constant_callers(&[WEB_CONTENTS_DEBUGGING], 0, is_true) {
        findings.push(finding(
            CodeRule::WebViewDebugging,
            api,
            callers,
            CodeEvidence::ConstantArgument,
            Some("true".to_owned()),
            "lets anyone with USB debugging inspect and script the app's WebViews: true at the \
             call site"
                .to_owned(),
        ));
    }
    for (api, _, callers) in index.constant_callers(&[SAFE_BROWSING], SETTING_SLOT, is_false) {
        findings.push(finding(
            CodeRule::SafeBrowsingDisabled,
            api,
            callers,
            CodeEvidence::ConstantArgument,
            Some("false".to_owned()),
            "turns Safe Browsing off for the WebView: false at the call site".to_owned(),
        ));
    }
    if safe_browsing_off_in_manifest(manifest) {
        findings.push(CodeFinding {
            rule: CodeRule::SafeBrowsingDisabled,
            api: Some(SAFE_BROWSING_META_DATA.to_owned()),
            callers: Vec::new(),
            caller_count: 0,
            version_checked_callers: 0,
            detail: format!(
                "the manifest sets {SAFE_BROWSING_META_DATA} to false: Safe Browsing is off in \
                 every WebView of the app"
            ),
            evidence: CodeEvidence::Manifest,
            argument: Some("false".to_owned()),
        });
    }
    let overriding = format!("{WEB_VIEW_CLIENT}{ON_RECEIVED_SSL_ERROR}");
    let proceeding: BTreeSet<String> = index
        .overrides
        .get(&overriding)
        .into_iter()
        .flatten()
        .filter(|(_, references)| references.contains(SSL_PROCEED))
        .map(|(method, _)| method.clone())
        .collect();
    if !proceeding.is_empty() {
        findings.push(finding(
            CodeRule::WebViewSslErrorProceed,
            &overriding,
            &proceeding,
            CodeEvidence::Override,
            None,
            "an override of WebViewClient.onReceivedSslError calls SslErrorHandler.proceed, \
             loading the page despite the certificate error; whether it proceeds on every \
             error is not established"
                .to_owned(),
        ));
    }
}

/// `<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" android:value="false">`
/// under `<application>`. A value given by reference is not resolved here, and does not count.
fn safe_browsing_off_in_manifest(manifest: &Manifest) -> bool {
    manifest.application.as_ref().is_some_and(|application| {
        application.meta_data.iter().any(|meta_data| {
            meta_data.name == SAFE_BROWSING_META_DATA
                && meta_data.value.as_ref().and_then(|value| value.as_bool()) == Some(false)
        })
    })
}

fn logging(index: &CallIndex, findings: &mut Vec<CodeFinding>) {
    for (api, callers) in index.reference_callers(&LOG_METHODS) {
        findings.push(finding(
            CodeRule::LoggingApi,
            api,
            callers,
            CodeEvidence::Reference,
            None,
            "writes to the system log, which other apps cannot read but anyone with the device \
             and USB debugging can; what is logged is not established"
                .to_owned(),
        ));
    }
    // Printing to System.out or System.err: a method that reads either stream and prints.
    let stream_readers: BTreeSet<&String> = STANDARD_STREAMS
        .iter()
        .filter_map(|field| index.fields.get(*field))
        .flatten()
        .collect();
    for (api, callers) in index.reference_callers(&PRINT_STREAM_PRINT) {
        let printing: BTreeSet<String> = callers
            .iter()
            .filter(|caller| stream_readers.contains(caller))
            .cloned()
            .collect();
        if !printing.is_empty() {
            findings.push(finding(
                CodeRule::LoggingApi,
                api,
                &printing,
                CodeEvidence::Reference,
                None,
                "prints to System.out or System.err, which Android sends to the system log; \
                 what is printed is not established"
                    .to_owned(),
            ));
        }
    }
}
