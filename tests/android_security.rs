//! Security code checks on msec's security fixtures (tests/fixtures/android/build_security.sh):
//! the constant arguments msec reads at call sites are those AOSP dexdump's disassembly shows
//! set on the only path into the call; calls whose argument is a parameter, a field or a value
//! merged from two branches are never taken for constants; the positive app gives exactly the
//! expected findings, each with what it rests on; the clean app gives none; and the app whose
//! second DEX file is truncated cannot be read in full.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::Path;

use msec::android::Apk;
use msec::android::analysis::{CodeEvidence, CodeRule};
use msec::android::dex::Constant;
use msec::archive::{Limits, ZipArchive};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/android");

fn apk(name: &str) -> Apk {
    let bytes = std::fs::read(Path::new(FIXTURES).join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Apk::read(&mut archive)
}

/// (caller, callee, slot, value) of every string constant argument msec reads, as text.
fn string_arguments(apk: &Apk) -> BTreeSet<(String, String, u8, String)> {
    let mut found = BTreeSet::new();
    for file in apk
        .dex_files
        .iter()
        .flat_map(|entry| &entry.container.files)
    {
        for argument in file.constant_arguments() {
            if let Constant::String(string) = argument.value {
                found.insert((
                    file.method_signature(argument.caller).unwrap(),
                    file.method_signature(argument.callee).unwrap(),
                    argument.slot,
                    file.string(string).unwrap().to_owned(),
                ));
            }
        }
    }
    found
}

/// Every string constant msec reports at a call is, in dexdump's disassembly of the caller, a
/// `const-string` of that value into a register the call passes; and the calls whose argument
/// is a parameter, a field or a merge of two branches report none.
#[test]
fn constant_arguments_are_those_set_on_the_only_path_into_the_call() {
    let apk = apk("security.apk");
    let found = string_arguments(&apk);
    let disassembly =
        std::fs::read_to_string(Path::new(FIXTURES).join("security/positive.disassembly.txt"))
            .unwrap();
    for (caller, _, _, value) in &found {
        // dexdump names the method `pkg.Class.name:(...)`: the class's simple name and the
        // method name are enough to find its block.
        let class = caller.split("->").next().unwrap();
        let simple = class.trim_end_matches(';').rsplit('/').next().unwrap();
        let name = caller
            .split("->")
            .nth(1)
            .unwrap()
            .split('(')
            .next()
            .unwrap();
        let header = format!("{simple}.{name}:");
        let block: String = disassembly
            .split("|[")
            .filter(|part| part.contains(&header))
            .collect();
        assert!(
            block.contains("const-string v") && block.contains(&format!("\"{value}\"")),
            "{caller}: {value}"
        );
    }
    let cipher = "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;";
    let shapes = "Ldev/appchk/fixture/security/CallShapes;->all(Ljava/lang/String;Z)V";
    assert!(
        !found
            .iter()
            .any(|(caller, callee, ..)| caller == shapes && callee == cipher),
        "{found:#?}"
    );
    let crypto = "Ldev/appchk/fixture/security/Crypto;->all()V";
    let at_cipher: BTreeSet<&str> = found
        .iter()
        .filter(|(caller, callee, slot, _)| caller == crypto && callee == cipher && *slot == 0)
        .map(|(.., value)| value.as_str())
        .collect();
    assert_eq!(
        at_cipher,
        BTreeSet::from([
            "AES",
            "AES/ECB/PKCS5Padding",
            "DES/CBC/PKCS5Padding",
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        ])
    );
    // Integer constants too: the mode passed to openFileOutput from the Activity.
    let main = "Ldev/appchk/fixture/security/MainActivity;->onCreate(Landroid/os/Bundle;)V";
    let modes: Vec<Constant> = apk
        .dex_files
        .iter()
        .flat_map(|entry| &entry.container.files)
        .flat_map(|file| {
            file.constant_arguments()
                .iter()
                .filter(|argument| {
                    file.method_signature(argument.caller).as_deref() == Some(main)
                        && file
                            .method_signature(argument.callee)
                            .is_some_and(|callee| callee.contains("->openFileOutput("))
                        && argument.slot == 2
                })
                .map(|argument| argument.value)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(modes, [Constant::Int(1)]);
}

/// (rule, API, argument, evidence, callers) of a security finding.
type Summary = (CodeRule, String, Option<String>, CodeEvidence, Vec<String>);
/// The same, borrowed, for comparing with expectations.
type Expected<'a> = (
    CodeRule,
    &'a str,
    Option<&'a str>,
    CodeEvidence,
    Vec<&'a str>,
);

fn security_findings(apk: &Apk) -> Vec<Summary> {
    apk.code_findings()
        .into_iter()
        .filter(|finding| CodeRule::SECURITY.contains(&finding.rule))
        .map(|finding| {
            (
                finding.rule,
                finding.api.unwrap_or_default(),
                finding.argument,
                finding.evidence,
                finding
                    .callers
                    .iter()
                    .map(|caller| {
                        caller
                            .method
                            .trim_start_matches("Ldev/appchk/fixture/security/")
                            .split('(')
                            .next()
                            .unwrap()
                            .to_owned()
                    })
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn the_positive_app_gives_each_expected_finding() {
    use CodeEvidence::{ConstantArgument, Manifest, Override, Reference};
    let findings = security_findings(&apk("security.apk"));
    let summary: Vec<Expected<'_>> = findings
        .iter()
        .map(|(rule, api, argument, evidence, callers)| {
            (
                *rule,
                api.as_str(),
                argument.as_deref(),
                *evidence,
                callers.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let cipher = "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;";
    let cipher_provider = "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/Cipher;";
    let digest = "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;";
    let crypto = vec!["Crypto;->all"];
    let expected: Vec<Expected<'_>> = vec![
        (
            CodeRule::CipherBrokenAlgorithm,
            cipher,
            Some("DES/CBC/PKCS5Padding"),
            ConstantArgument,
            crypto.clone(),
        ),
        (
            CodeRule::CipherBrokenAlgorithm,
            cipher_provider,
            Some("RC4"),
            ConstantArgument,
            crypto.clone(),
        ),
        (
            CodeRule::CipherEcbMode,
            cipher,
            Some("AES/ECB/PKCS5Padding"),
            ConstantArgument,
            crypto.clone(),
        ),
        (
            CodeRule::CipherDefaultMode,
            cipher,
            Some("AES"),
            ConstantArgument,
            crypto.clone(),
        ),
        (
            CodeRule::WeakHash,
            digest,
            Some("MD5"),
            ConstantArgument,
            crypto.clone(),
        ),
        (
            CodeRule::WeakHash,
            digest,
            Some("SHA-1"),
            ConstantArgument,
            crypto.clone(),
        ),
        (
            CodeRule::InsecureRandom,
            "Ljava/lang/Math;->random()D",
            None,
            Reference,
            crypto.clone(),
        ),
        (
            CodeRule::InsecureRandom,
            "Ljava/util/Random;-><init>()V",
            None,
            Reference,
            crypto.clone(),
        ),
        // Called through the Activity and on a Context: both reach Context.openFileOutput.
        (
            CodeRule::WorldAccessibleFiles,
            "Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
            Some("MODE_WORLD_WRITEABLE"),
            ConstantArgument,
            vec!["Storage;->all"],
        ),
        (
            CodeRule::WorldAccessibleFiles,
            "Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;",
            Some("MODE_WORLD_READABLE"),
            ConstantArgument,
            vec!["MainActivity;->onCreate", "Storage;->all"],
        ),
        (
            CodeRule::ExternalStorage,
            "Landroid/content/Context;->getExternalFilesDir(Ljava/lang/String;)Ljava/io/File;",
            None,
            Reference,
            vec!["Storage;->all"],
        ),
        (
            CodeRule::ExternalStorage,
            "Landroid/os/Environment;->getExternalStorageDirectory()Ljava/io/File;",
            None,
            Reference,
            vec!["Storage;->all"],
        ),
        (
            CodeRule::WebViewBridgeReflection,
            "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V",
            None,
            Reference,
            vec!["WebViews;->all"],
        ),
        (
            CodeRule::WebViewFileUrlAccess,
            "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V",
            Some("true"),
            ConstantArgument,
            vec!["WebViews;->all"],
        ),
        (
            CodeRule::WebViewFileUrlAccess,
            "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V",
            Some("true"),
            ConstantArgument,
            vec!["WebViews;->all"],
        ),
        (
            CodeRule::WebViewFileAccess,
            "Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V",
            Some("true"),
            ConstantArgument,
            vec!["WebViews;->all"],
        ),
        (
            CodeRule::WebViewContentAccess,
            "Landroid/webkit/WebSettings;->setAllowContentAccess(Z)V",
            Some("true"),
            ConstantArgument,
            vec!["WebViews;->all"],
        ),
        (
            CodeRule::WebViewSslErrorProceed,
            "Landroid/webkit/WebViewClient;->onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V",
            None,
            Override,
            vec!["InsecureClient;->onReceivedSslError"],
        ),
        (
            CodeRule::WebViewDebugging,
            "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V",
            Some("true"),
            ConstantArgument,
            vec!["WebViews;->all"],
        ),
        (
            CodeRule::SafeBrowsingDisabled,
            "Landroid/webkit/WebSettings;->setSafeBrowsingEnabled(Z)V",
            Some("false"),
            ConstantArgument,
            vec!["WebViews;->all"],
        ),
        (
            CodeRule::SafeBrowsingDisabled,
            "android.webkit.WebView.EnableSafeBrowsing",
            Some("false"),
            Manifest,
            vec![],
        ),
        (
            CodeRule::LoggingApi,
            "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I",
            None,
            Reference,
            vec!["Logging;->all"],
        ),
        (
            CodeRule::LoggingApi,
            "Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I",
            None,
            Reference,
            vec!["Logging;->all"],
        ),
        (
            CodeRule::LoggingApi,
            "Ljava/io/PrintStream;->println(Ljava/lang/String;)V",
            None,
            Reference,
            vec!["Logging;->all"],
        ),
    ];
    let mut actual = summary.clone();
    actual.sort();
    let mut expected = expected;
    expected.sort();
    assert_eq!(actual, expected, "{findings:#?}");
}

/// The same features done safely give no security finding.
#[test]
fn the_clean_app_gives_none() {
    let findings = security_findings(&apk("security-clean.apk"));
    assert!(findings.is_empty(), "{findings:#?}");
}

/// The incomplete app's second DEX file cannot be read in full; what is read (the clean code)
/// gives no finding. APPCHK makes these rules inconclusive from that (`dex` gap).
#[test]
fn the_incomplete_app_cannot_be_read_in_full() {
    let apk = apk("security-incomplete.apk");
    assert_eq!(apk.dex_files.len(), 2);
    assert!(apk.dex_files[0].container.complete());
    assert!(!apk.dex_files[1].container.complete());
    assert!(security_findings(&apk).is_empty());
}

/// Above API 17 the bridge exposes only annotated methods; from API 24 world modes are refused.
/// The clean manifest's SDK levels applied to the positive code give the other rule of each pair.
#[test]
fn sdk_levels_choose_between_the_rules_of_a_pair() {
    let mut positive = apk("security.apk");
    let clean = apk("security-clean.apk");
    positive.manifest = clean.manifest.clone();
    positive.manifest_document = clean.manifest_document.clone();
    let rules: BTreeSet<CodeRule> = security_findings(&positive)
        .into_iter()
        .map(|(rule, ..)| rule)
        .collect();
    assert!(rules.contains(&CodeRule::WebViewBridge));
    assert!(!rules.contains(&CodeRule::WebViewBridgeReflection));
    assert!(rules.contains(&CodeRule::WorldAccessibleFilesRefused));
    assert!(!rules.contains(&CodeRule::WorldAccessibleFiles));
    // Safe Browsing: the clean manifest has no meta-data, so only the call remains.
    let safe_browsing = security_findings(&positive)
        .into_iter()
        .filter(|(rule, ..)| *rule == CodeRule::SafeBrowsingDisabled)
        .count();
    assert_eq!(safe_browsing, 1);
}
