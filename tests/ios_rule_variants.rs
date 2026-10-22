//! The rule-variant IPAs (tests/fixtures/ios/build_rule_variants.sh): fixture.ipa changed in
//! one way each, for checks no other IPA fixture triggers. Each change is what Apple's tools
//! read in the file (variant-verdicts.txt), and msec reports it on the main executable or the
//! app.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{AppRule, BinaryRule, analyse_app, analyse_binaries};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");
const MAIN: &str = "Payload/Fixture.app/Fixture";

fn read_ipa(name: &str) -> Ipa {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Ipa::read(&mut archive)
}

/// variant-verdicts.txt: per variant, its indented lines.
fn oracle() -> BTreeMap<String, Vec<String>> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("variant-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        if let Some(variant) = line.strip_suffix(':') {
            current = variant.to_owned();
            readings.insert(current.clone(), Vec::new());
        } else if let Some(seen) = line.strip_prefix("  ") {
            readings.get_mut(&current).unwrap().push(seen.to_owned());
        }
    }
    readings
}

/// The rules msec reports on the main executable.
fn main_rules(name: &str) -> BTreeSet<BinaryRule> {
    let ipa = read_ipa(name);
    analyse_binaries(ipa.app.as_ref().unwrap())
        .into_iter()
        .filter(|finding| finding.binary == MAIN)
        .map(|finding| finding.rule)
        .collect()
}

#[test]
fn each_binary_variant_is_reported_as_apples_tools_read_it() {
    let oracle = oracle();
    let has = |variant: &str, line: &str| oracle[variant].iter().any(|seen| seen == line);
    // MH_PIE cleared.
    assert!(has("variant-no-pie", "flags: none"));
    assert!(main_rules("variant-no-pie.ipa").contains(&BinaryRule::NotPie));
    // MH_ALLOW_STACK_EXECUTION set.
    assert!(has(
        "variant-stack-exec",
        "flags: ALLOW_STACK_EXECUTION PIE "
    ));
    assert!(main_rules("variant-stack-exec.ipa").contains(&BinaryRule::ExecutableStack));
    // Objective-C without the ARC runtime calls nm would list.
    assert!(
        !oracle["variant-manual"]
            .iter()
            .any(|seen| seen.contains("objc_release"))
    );
    assert!(main_rules("variant-manual.ipa").contains(&BinaryRule::NoArc));
    // Debug entries in the symbol table.
    assert!(has("variant-debug", "debug entries: 9"));
    assert!(main_rules("variant-debug.ipa").contains(&BinaryRule::DebugSymbols));
    // strcpy, not __strcpy_chk.
    assert!(has("variant-unfortified", "import _strcpy"));
    assert!(main_rules("variant-unfortified.ipa").contains(&BinaryRule::UnboundedFunctions));
    // rand and srand, and a library search path outside the bundle.
    assert!(has("variant-random-rpath", "import _rand"));
    assert!(has("variant-random-rpath", "rpath: /usr/local/lib"));
    let random = main_rules("variant-random-rpath.ipa");
    assert!(random.contains(&BinaryRule::InsecureRandom));
    assert!(random.contains(&BinaryRule::RpathOutsideBundle));
    // No signature at all.
    assert!(has(
        "variant-unsigned",
        "codesign: code object is not signed at all"
    ));
    assert!(main_rules("variant-unsigned.ipa").contains(&BinaryRule::Unsigned));
    // DER entitlements that differ from the XML ones.
    assert!(main_rules("variant-der-mismatch.ipa").contains(&BinaryRule::EntitlementsDiffer));
}

/// Exceptions for web content, media and local networking, and a domain allowing plain HTTP
/// without forward secrecy, with NSAllowsArbitraryLoads unset.
#[test]
fn ats_exceptions_are_reported() {
    let ats = &oracle()["variant-ats-exceptions"];
    assert!(ats.iter().any(|seen| seen.starts_with("ats: ")
        && seen.contains("\"NSAllowsArbitraryLoadsInWebContent\":true")
        && seen.contains("\"NSExceptionAllowsInsecureHTTPLoads\":true")
        && !seen.contains("\"NSAllowsArbitraryLoads\":")));
    let ipa = read_ipa("variant-ats-exceptions.ipa");
    let rules: BTreeSet<AppRule> = analyse_app(ipa.app.as_ref().unwrap(), "2026-10-22")
        .into_iter()
        .map(|finding| finding.rule)
        .collect();
    for rule in [
        AppRule::AtsWebContent,
        AppRule::AtsMedia,
        AppRule::AtsLocalNetworking,
        AppRule::AtsInsecureHttpDomain,
        AppRule::AtsForwardSecrecyDisabled,
    ] {
        assert!(rules.contains(&rule), "{rule:?}: {rules:?}");
    }
    assert!(!rules.contains(&AppRule::AtsArbitraryLoads));
}
