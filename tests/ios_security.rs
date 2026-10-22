//! The iOS crypto, storage, WebView and logging checks on the security fixtures
//! (tests/fixtures/ios/build_security.sh): what each executable imports, and the WebKit
//! preference keys its C strings name, are what `nm -u` and `otool` show
//! (security-verdicts.txt); the clean app gives no finding; an executable the App Store
//! encrypted, or one cut short, leaves the checks that needed the unread part unchecked, never
//! clean.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{BinaryEvidence, BinaryRule, analyse_binaries};
use msec::ios::coverage::{UncheckedCause, UncheckedCheck, unchecked};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

/// The checks of this slice, and the weak-hash check they extend with CryptoKit.
const SECURITY_RULES: [BinaryRule; 6] = [
    BinaryRule::WeakHashes,
    BinaryRule::LoggingApi,
    BinaryRule::FileProtectionNone,
    BinaryRule::KeychainAccessibleAlways,
    BinaryRule::UiWebView,
    BinaryRule::WebViewFileOriginRelaxed,
];

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

/// security-verdicts.txt: per `<variant> <executable>`, its `import <symbol>`, `string <key>`
/// and other lines.
fn oracle() -> BTreeMap<String, BTreeSet<String>> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("security-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(binary) = line.strip_suffix(':') {
            current = binary.to_owned();
            readings.insert(current.clone(), BTreeSet::new());
        } else if let Some(seen) = line.strip_prefix("  ") {
            readings.get_mut(&current).unwrap().insert(seen.to_owned());
        }
    }
    readings
}

/// `(rule, executable within the app, detail)` of this slice's findings.
fn security_findings(ipa: &Ipa) -> Vec<(BinaryRule, String, String)> {
    let app = ipa.app.as_ref().unwrap();
    analyse_binaries(app)
        .into_iter()
        .filter(|finding| SECURITY_RULES.contains(&finding.rule))
        .map(|finding| {
            let binary = finding
                .binary
                .strip_prefix(app.path.as_str())
                .unwrap()
                .to_owned();
            (finding.rule, binary, finding.detail)
        })
        .collect()
}

/// The names a finding's detail lists after "imports " (up to the first colon).
fn imported_names(detail: &str) -> Vec<&str> {
    detail
        .strip_prefix("imports ")
        .unwrap()
        .split(':')
        .next()
        .unwrap()
        .split(", ")
        .collect()
}

/// The positive app: one finding per rule and executable, each naming exactly what Apple's
/// tools show it imports or names.
#[test]
fn findings_are_what_nm_and_otool_show() {
    let oracle = oracle();
    let findings = security_findings(&read_ipa("security.ipa"));
    let summary: Vec<(BinaryRule, &str)> = findings
        .iter()
        .map(|(rule, binary, _)| (*rule, binary.as_str()))
        .collect();
    assert_eq!(
        summary,
        [
            (BinaryRule::WeakHashes, "Frameworks/Lib.framework/Lib"),
            (BinaryRule::LoggingApi, "Fixture"),
            (BinaryRule::LoggingApi, "Frameworks/Lib.framework/Lib"),
            (BinaryRule::FileProtectionNone, "Fixture"),
            (BinaryRule::KeychainAccessibleAlways, "Fixture"),
            (BinaryRule::UiWebView, "Fixture"),
            (BinaryRule::WebViewFileOriginRelaxed, "Fixture"),
            (
                BinaryRule::WebViewFileOriginRelaxed,
                "Frameworks/Lib.framework/Lib"
            ),
        ]
    );
    let detail = |rule: BinaryRule, binary: &str| -> &str {
        &findings
            .iter()
            .find(|(found, path, _)| *found == rule && path == binary)
            .unwrap()
            .2
    };
    let main = &oracle["positive Fixture"];
    let library = &oracle["positive Frameworks/Lib.framework/Lib"];
    let imports =
        |seen: &BTreeSet<String>, symbol: &str| seen.contains(&format!("import {symbol}"));
    // Every name msec gives is a symbol nm lists.
    assert_eq!(
        imported_names(detail(BinaryRule::LoggingApi, "Fixture")),
        ["NSLog", "NSLogv", "printf"]
    );
    assert!(
        ["NSLog", "NSLogv", "printf"]
            .iter()
            .all(|name| imports(main, name))
    );
    assert_eq!(
        imported_names(detail(
            BinaryRule::LoggingApi,
            "Frameworks/Lib.framework/Lib"
        )),
        ["print (Swift)", "debugPrint (Swift)"]
    );
    assert!(imports(
        library,
        "$ss5print_9separator10terminatoryypd_S2StF"
    ));
    assert!(imports(
        library,
        "$ss10debugPrint_9separator10terminatoryypd_S2StF"
    ));
    assert_eq!(
        imported_names(detail(BinaryRule::FileProtectionNone, "Fixture")),
        ["NSFileProtectionNone", "NSURLFileProtectionNone"]
    );
    assert!(imports(main, "NSFileProtectionNone") && imports(main, "NSURLFileProtectionNone"));
    assert_eq!(
        imported_names(detail(BinaryRule::KeychainAccessibleAlways, "Fixture")),
        [
            "kSecAttrAccessibleAlways",
            "kSecAttrAccessibleAlwaysThisDeviceOnly"
        ]
    );
    assert!(imports(main, "kSecAttrAccessibleAlways"));
    assert!(imports(main, "kSecAttrAccessibleAlwaysThisDeviceOnly"));
    assert!(detail(BinaryRule::UiWebView, "Fixture").starts_with("references UIWebView: "));
    assert!(imports(main, "OBJC_CLASS_$_UIWebView"));
    assert!(detail(BinaryRule::UiWebView, "Fixture").contains("ITMS-90809"));
    // CryptoKit's insecure hashes, from the Swift metadata nm lists.
    assert_eq!(
        imported_names(detail(
            BinaryRule::WeakHashes,
            "Frameworks/Lib.framework/Lib"
        )),
        ["Insecure.MD5", "Insecure.SHA1"]
    );
    assert!(imports(library, "$s9CryptoKit8InsecureO3MD5VMa"));
    assert!(imports(library, "$s9CryptoKit8InsecureO4SHA1VMa"));
    // The keys otool prints in __cstring, from Objective-C and from Swift.
    for (binary, keys) in [
        (
            "Fixture",
            "allowFileAccessFromFileURLs, allowUniversalAccessFromFileURLs",
        ),
        (
            "Frameworks/Lib.framework/Lib",
            "allowFileAccessFromFileURLs",
        ),
    ] {
        let found = detail(BinaryRule::WebViewFileOriginRelaxed, binary);
        assert!(
            found.starts_with(&format!("names the WebKit preference {keys} ")),
            "{found}"
        );
        let seen = &oracle[&format!("positive {binary}")];
        for key in keys.split(", ") {
            assert!(seen.contains(&format!("string {key}")), "{binary}: {key}");
        }
    }
}

/// What each finding rests on: imports, except the WebKit preference key, a string.
#[test]
fn findings_say_what_they_rest_on() {
    for rule in SECURITY_RULES {
        let expected = if rule == BinaryRule::WebViewFileOriginRelaxed {
            BinaryEvidence::String
        } else {
            BinaryEvidence::Import
        };
        assert_eq!(rule.evidence(), Some(expected), "{rule:?}");
    }
    assert_eq!(BinaryRule::NotPie.evidence(), None);
    assert_eq!(BinaryRule::GetTaskAllow.evidence(), None);
}

/// The safe counterparts give no finding of these rules, and nothing is unchecked.
#[test]
fn the_clean_app_gives_no_finding() {
    let oracle = oracle();
    for variant in ["clean Fixture", "clean Frameworks/Lib.framework/Lib"] {
        assert!(
            oracle[variant].is_empty(),
            "{variant}: {:?}",
            oracle[variant]
        );
    }
    let ipa = read_ipa("security-clean.ipa");
    assert_eq!(security_findings(&ipa), []);
    assert_eq!(unchecked(ipa.app.as_ref().unwrap()), []);
}

/// The clean app as delivered encrypted, with its framework cut short: the main executable's
/// strings and method names are unchecked (encrypted) and the framework's imports are
/// unchecked (its symbol table is outside the file), so the checks that needed them are
/// incomplete. The framework's unread imports are not read as missing protections.
#[test]
fn unread_parts_are_unchecked_not_clean() {
    let oracle = oracle();
    assert!(oracle["incomplete Fixture"].contains("cryptid 1"));
    assert!(
        oracle["incomplete Frameworks/Lib.framework/Lib"]
            .iter()
            .any(|line| line.starts_with("nm error: truncated or malformed object"))
    );
    let ipa = read_ipa("security-incomplete.ipa");
    let app = ipa.app.as_ref().unwrap();
    assert_eq!(security_findings(&ipa), []);
    let parts: Vec<(UncheckedCheck, UncheckedCause, String)> = unchecked(app)
        .into_iter()
        .map(|part| {
            let location = part
                .location
                .strip_prefix(app.path.as_str())
                .unwrap()
                .to_owned();
            (part.check, part.cause, location)
        })
        .collect();
    assert_eq!(
        parts,
        [
            (
                UncheckedCheck::PageHashes,
                UncheckedCause::Encrypted,
                "Fixture".to_owned()
            ),
            (
                UncheckedCheck::Strings,
                UncheckedCause::Encrypted,
                "Fixture".to_owned()
            ),
            (
                UncheckedCheck::MethodNames,
                UncheckedCause::Encrypted,
                "Fixture".to_owned()
            ),
            // Cut at __LINKEDIT: the symbol table is gone, __TEXT (its strings) is whole.
            (
                UncheckedCheck::Imports,
                UncheckedCause::Malformed,
                "Frameworks/Lib.framework/Lib".to_owned()
            ),
        ]
    );
    let keys = |check: UncheckedCheck| check.keys();
    for rule in BinaryRule::READ_IMPORTS {
        assert!(
            keys(UncheckedCheck::Imports).contains(&rule.key()),
            "{rule:?}"
        );
    }
    assert!(keys(UncheckedCheck::Strings).contains(&BinaryRule::WebViewFileOriginRelaxed.key()));
    // The cut framework: no hardening heuristic fires on imports that were never read, and
    // its signature, whose LC_CODE_SIGNATURE points past the end of the file, is unreadable,
    // not missing.
    let library: Vec<(BinaryRule, String)> = analyse_binaries(app)
        .into_iter()
        .filter(|finding| finding.binary.ends_with("Lib.framework/Lib"))
        .map(|finding| (finding.rule, finding.detail))
        .collect();
    assert_eq!(
        library,
        [(
            BinaryRule::SignatureMismatch,
            "the code signature cannot be read: LC_CODE_SIGNATURE points outside the file"
                .to_owned()
        )]
    );
}
