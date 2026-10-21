//! msec's plist reader against Core Foundation's, through `plutil` (tests/fixtures/plist,
//! rebuilt by build_plist.sh): the same verdict on every crafted file (binary, XML, and OpenStep
//! text and `.strings` files), and for every file both read, the XML `plutil -convert xml1`
//! writes, byte for byte.

use std::path::Path;
use std::time::{Duration, Instant};

use msec::plist::{Anomaly, Format, PlistError, Value, parse, to_xml};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plist");

/// Files where msec deliberately does not follow Core Foundation, and the error it gives
/// instead of reading them.
fn divergence(file: &str) -> Option<fn(&PlistError) -> bool> {
    match file {
        // Encodings other than UTF-8, UTF-16 and ISO-8859-1 are not read.
        "xml/shift-jis.xml" => Some(|error| matches!(error, PlistError::UnsupportedEncoding(_))),
        // Binary format 1x is not read (Core Foundation refuses this file too: it is a bplist00
        // body under a 1x header).
        "binary/version-10.bplist" => Some(|error| matches!(error, PlistError::Unsupported(_))),
        // Core Foundation shares objects; msec copies them, within a budget.
        "binary/expansion-bomb.bplist" => {
            Some(|error| matches!(error, PlistError::ExpansionBudgetExhausted))
        }
        _ => None,
    }
}

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(Path::new(FIXTURES).join(relative)).unwrap()
}

/// `(file, accepted)` for every fixture, from plutil's verdicts.
fn verdicts() -> Vec<(String, bool)> {
    let text = String::from_utf8(read("verdicts.txt")).unwrap();
    text.lines()
        .map(|line| {
            let (file, verdict) = line.split_once(": ").unwrap();
            (file.to_owned(), verdict == "accepted")
        })
        .collect()
}

#[test]
fn verdicts_match_core_foundation() {
    let verdicts = verdicts();
    assert!(verdicts.len() > 100, "{} fixtures", verdicts.len());
    let mut compared = 0;
    let mut compared_openstep = 0;
    for (file, accepted) in verdicts {
        let result = parse(&read(&file));
        if let Some(expected_error) = divergence(&file) {
            let error = result.expect_err(&file);
            assert!(expected_error(&error), "{file}: {error:?}");
            assert!(!error.rejected_by_core_foundation(), "{file}");
            continue;
        }
        let plist = match (result, accepted) {
            (Ok(plist), true) => plist,
            (Err(error), false) => {
                assert!(error.rejected_by_core_foundation(), "{file}: {error:?}");
                continue;
            }
            (result, accepted) => {
                panic!("{file}: plutil {accepted}, msec {result:?}")
            }
        };
        // Core Foundation keeps an unpaired surrogate, then cannot write it (plutil writes an
        // empty string); msec substitutes U+FFFD and says so.
        if plist
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly, Anomaly::InvalidUtf16 { .. }))
        {
            continue;
        }
        let name = Path::new(&file).file_name().unwrap().to_str().unwrap();
        let Ok(expected) = std::fs::read_to_string(
            Path::new(FIXTURES)
                .join("expected")
                .join(format!("{name}.xml")),
        ) else {
            continue;
        };
        assert_eq!(to_xml(&plist.root).unwrap(), expected, "{file}");
        compared += 1;
        compared_openstep += usize::from(file.starts_with("openstep/"));
    }
    assert!(
        compared >= 30,
        "{compared} files compared with plutil's XML"
    );
    assert!(
        compared_openstep >= 25,
        "{compared_openstep} OpenStep files compared with plutil's XML"
    );
}

/// The same content in both formats: Xcode's binary Info.plist reads as its XML source.
#[test]
fn both_formats_read_the_same() {
    for name in ["info", "types"] {
        let xml = parse(&read(&format!("xml/{name}.xml"))).unwrap();
        let binary = parse(&read(&format!("binary/{name}.bplist"))).unwrap();
        assert_eq!((xml.format, binary.format), (Format::Xml, Format::Binary));
        assert_eq!(to_xml(&xml.root), to_xml(&binary.root), "{name}");
    }
    let info = parse(&read("binary/info.bplist")).unwrap().root;
    assert_eq!(
        info.get("CFBundleIdentifier").and_then(Value::as_str),
        Some("dev.appchk.fixture")
    );
    assert_eq!(
        info.get("NSAppTransportSecurity")
            .and_then(|ats| ats.get("NSAllowsArbitraryLoads"))
            .and_then(Value::as_bool),
        Some(true)
    );
    let families: Vec<i128> = info
        .get("UIDeviceFamily")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .filter_map(Value::as_integer)
        .collect();
    assert_eq!(families, [1, 2]);
}

/// A repeated key: Core Foundation keeps the first value in a binary plist and the last in an
/// XML one, and msec records the repetition either way.
#[test]
fn duplicate_keys_resolve_as_core_foundation_resolves_them() {
    let binary = parse(&read("binary/duplicate-key.bplist")).unwrap();
    assert_eq!(binary.root.get("a"), Some(&Value::Integer(1)));
    let xml = parse(&read("xml/duplicate-key.xml")).unwrap();
    assert_eq!(xml.root.get("a"), Some(&Value::Integer(2)));
    for plist in [binary, xml] {
        assert_eq!(
            plist.anomalies,
            [Anomaly::DuplicateKey {
                path: "/".into(),
                key: "a".into()
            }]
        );
    }
    // The same key in two string encodings is still the same key.
    let two = parse(&read("binary/duplicate-key-two-encodings.bplist")).unwrap();
    assert_eq!(two.root.get("a"), Some(&Value::Integer(1)));
    assert_eq!(two.anomalies.len(), 1);
}

#[test]
fn anomalies_name_what_core_foundation_reads_differently() {
    let surrogate = parse(&read("binary/lone-surrogate.bplist")).unwrap();
    assert_eq!(
        surrogate.anomalies,
        [Anomaly::InvalidUtf16 { path: "/".into() }]
    );
    let wide = parse(&read("binary/integer-128-wide.bplist")).unwrap();
    assert_eq!(wide.root, Value::Integer(5));
    assert_eq!(wide.anomalies, [Anomaly::WideInteger { path: "/".into() }]);
    let negative = parse(&read("binary/integer-128-negative.bplist")).unwrap();
    assert_eq!(negative.root, Value::Integer(18_446_744_073_709_551_611));
    // Binary-only objects Core Foundation reads but cannot write as XML.
    let null = parse(&read("binary/null.bplist")).unwrap();
    assert_eq!(null.root, Value::Array(vec![Value::Null]));
    assert!(to_xml(&null.root).is_err());
    let set = parse(&read("binary/set.bplist")).unwrap();
    assert_eq!(set.root, Value::Set(vec![Value::Integer(1)]));
}

/// Depth and expansion stop where they should, and quickly.
#[test]
fn hostile_plists_stop_early() {
    let started = Instant::now();
    assert_eq!(
        parse(&read("binary/expansion-bomb.bplist")),
        Err(PlistError::ExpansionBudgetExhausted)
    );
    assert_eq!(
        parse(&read("binary/depth-513-and-integer.bplist")),
        Err(PlistError::TooDeep)
    );
    assert_eq!(parse(&read("xml/depth-512.xml")), Err(PlistError::TooDeep));
    // Entity declarations never get read.
    assert!(matches!(
        parse(&read("xml/entity-expansion.xml")),
        Err(PlistError::InvalidXml { reason, .. }) if reason == "DTD internal subset"
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// Every single-byte change to Apple-written binary plists, and every truncation, is read or
/// refused without panicking.
#[test]
fn edited_binary_plists_never_panic() {
    for name in ["binary/info.bplist", "binary/types.bplist"] {
        let original = read(name);
        for position in 0..original.len() {
            for value in [0x00, 0xFF, original[position] ^ 0x01] {
                let mut edited = original.clone();
                edited[position] = value;
                let _ = parse(&edited);
            }
            let _ = parse(&original[..position]);
        }
    }
}
