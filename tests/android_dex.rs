//! DEX reading, checked against AOSP's `dexdump` (ART's own loader and verifier): d8's output
//! in every version it writes, a version 041 container, and hostile files that each break one
//! rule. `tests/fixtures/android/build_dex.sh` builds the fixtures and records what dexdump
//! reads (`*.dexdump.txt`) and whether ART accepts each hostile file (`art-verdicts.txt`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use msec::android::Apk;
use msec::android::dex::{
    DexAnomalyKind, DexContainer, DexError, DexFile, MapProblem, PackageCount, ShadowedClass, parse,
};
use msec::archive::{Limits, ZipArchive};

const CODE_APK: &[u8] = include_bytes!("fixtures/android/code.apk");

fn dex_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/android/dex")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(dex_dir().join(name)).unwrap()
}

/// One logical file as dexdump prints it.
#[derive(Debug, Default)]
struct Dumped {
    header: BTreeMap<String, String>,
    /// `None` where dexdump printed "skipped (not printable)".
    strings: Vec<Option<String>>,
    classes: Vec<DumpedClass>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DumpedClass {
    descriptor: String,
    access_flags: u32,
    superclass: Option<String>,
    interfaces: Vec<String>,
}

fn quoted(line: &str) -> String {
    let start = line.find('\'').unwrap() + 1;
    line[start..line.rfind('\'').unwrap()].to_owned()
}

/// Parses `dexdump -n -f -s` output: per logical file, the header, the strings and the classes
/// (descriptor, access flags, superclass, interfaces).
fn dexdump(name: &str) -> Vec<Dumped> {
    let text = std::fs::read_to_string(dex_dir().join(name)).unwrap();
    let mut files: Vec<Dumped> = Vec::new();
    let mut in_interfaces = false;
    for line in text.lines() {
        if line == "DEX file header:" {
            files.push(Dumped::default());
            continue;
        }
        let Some(file) = files.last_mut() else {
            continue;
        };
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("string[") {
            let text = quoted(rest);
            file.strings
                .push((text != "skipped (not printable)").then_some(text));
        } else if line.starts_with("Class #") {
            file.classes.push(DumpedClass::default());
        } else if let Some(class) = file.classes.last_mut() {
            if trimmed.starts_with("Class descriptor") {
                class.descriptor = quoted(line);
            } else if trimmed.starts_with("Access flags") {
                let hex = trimmed
                    .split(": 0x")
                    .nth(1)
                    .unwrap()
                    .split(' ')
                    .next()
                    .unwrap();
                class.access_flags = u32::from_str_radix(hex, 16).unwrap();
            } else if trimmed.starts_with("Superclass") {
                class.superclass = Some(quoted(line));
            } else if trimmed.starts_with("Interfaces") {
                in_interfaces = true;
            } else if trimmed.starts_with("Static fields") {
                in_interfaces = false;
            } else if in_interfaces && trimmed.starts_with('#') {
                class.interfaces.push(quoted(line));
            }
        } else if let Some((key, value)) = line.split_once(" : ") {
            let value = value.trim().split(' ').next().unwrap().to_owned();
            file.header.insert(key.trim().to_owned(), value);
        }
    }
    files
}

fn number(dumped: &Dumped, key: &str) -> u32 {
    dumped.header[key].parse().unwrap()
}

/// Checks one logical file against dexdump's view of it.
fn assert_matches_dexdump(file: &DexFile, dumped: &Dumped, name: &str) {
    let header = &file.header;
    assert_eq!(
        format!("{:08x}", header.checksum),
        dumped.header["checksum"],
        "{name}"
    );
    assert_eq!(header.file_size, number(dumped, "file_size"), "{name}");
    assert_eq!(header.header_size, number(dumped, "header_size"), "{name}");
    if header.version >= 41 {
        assert_eq!(header.container_size, number(dumped, "container_size"));
        assert_eq!(header.header_offset, number(dumped, "header_off"));
    }
    for (key, table) in [
        ("string_ids", header.string_ids),
        ("type_ids", header.type_ids),
        ("proto_ids", header.proto_ids),
        ("field_ids", header.field_ids),
        ("method_ids", header.method_ids),
        ("class_defs", header.class_defs),
    ] {
        assert_eq!(
            table.count,
            number(dumped, &format!("{key}_size")),
            "{name} {key}"
        );
        assert_eq!(
            table.offset,
            number(dumped, &format!("{key}_off")),
            "{name} {key}"
        );
    }
    assert!(file.checksum_valid && file.signature_valid, "{name}");
    assert!(file.anomalies.is_empty(), "{name}: {:?}", file.anomalies);
    assert!(file.complete(), "{name}");

    let strings: Vec<Option<&str>> = file.strings().collect();
    assert_eq!(strings.len(), dumped.strings.len(), "{name}");
    for (index, (ours, theirs)) in strings.iter().zip(&dumped.strings).enumerate() {
        let ours = ours.unwrap_or_else(|| panic!("{name}: string {index} not read"));
        if let Some(theirs) = theirs {
            assert_eq!(ours, theirs, "{name}: string {index}");
        }
    }

    let classes: Vec<DumpedClass> = file
        .classes
        .iter()
        .map(|class| DumpedClass {
            descriptor: file.class_descriptor(class).unwrap().to_owned(),
            access_flags: class.access_flags,
            superclass: file.superclass(class).map(str::to_owned),
            interfaces: file
                .interfaces(class)
                .map(|interface| interface.unwrap().to_owned())
                .collect(),
        })
        .collect();
    assert_eq!(classes, dumped.classes, "{name}");
}

#[test]
fn every_version_d8_writes_reads_as_dexdump_reads_it() {
    for (name, version) in [
        ("v035", 35),
        ("v037", 37),
        ("v038", 38),
        ("v039", 39),
        ("v041", 41),
    ] {
        let container = parse(&read(&format!("{name}.dex")));
        assert!(container.complete(), "{name}: {:?}", container.error);
        let dumped = dexdump(&format!("{name}.dexdump.txt"));
        assert_eq!(container.files.len(), dumped.len(), "{name}");
        assert_eq!(container.files[0].version(), version);
        assert_matches_dexdump(&container.files[0], &dumped[0], name);
        assert_eq!(container.files[0].classes.len(), 9, "{name}");
    }
}

#[test]
fn a_container_yields_every_logical_file() {
    let bytes = read("container.dex");
    let container = parse(&bytes);
    assert!(container.complete(), "{:?}", container.error);
    let dumped = dexdump("container.dexdump.txt");
    assert_eq!(container.files.len(), 2);
    assert_eq!(dumped.len(), 2);
    for (file, dumped) in container.files.iter().zip(&dumped) {
        assert_matches_dexdump(file, dumped, "container");
    }
    let second = &container.files[1];
    assert_eq!(
        second.header.header_offset,
        container.files[0].header.file_size
    );
    assert_eq!(second.header.container_size as usize, bytes.len());
    let descriptors: Vec<&str> = container
        .files
        .iter()
        .flat_map(|file| {
            file.classes
                .iter()
                .map(|class| file.class_descriptor(class).unwrap())
        })
        .collect();
    assert_eq!(descriptors, ["LA;", "LB;", "LC;"]);
}

/// The strings dexdump does not print: MUTF-8's two- and three-byte forms, U+0000 as C0 80,
/// surrogate pairs and a lone surrogate. Their order (UTF-16 code units, which puts surrogates
/// before U+E000) passed the sort check, since the file has no anomalies.
#[test]
fn mutf8_strings_decode() {
    let container = parse(&read("v035.dex"));
    let file = &container.files[0];
    let strings: Vec<&str> = file.strings().map(Option::unwrap).collect();
    for expected in ["a\0b", "caf\u{e9}", "\u{e000}", "\u{1f600}", "\u{fffd}"] {
        assert!(strings.contains(&expected), "{expected:?} in {strings:?}");
    }
    let lone = strings.iter().position(|text| *text == "\u{fffd}").unwrap();
    let emoji = strings
        .iter()
        .position(|text| *text == "\u{1f600}")
        .unwrap();
    let private_use = strings.iter().position(|text| *text == "\u{e000}").unwrap();
    assert!(lone < emoji && emoji < private_use);
}

#[test]
fn compiler_markers_name_the_toolchain() {
    let container = parse(&read("v035.dex"));
    let markers: Vec<&str> = container.files[0].compiler_markers().collect();
    assert_eq!(markers.len(), 1, "{markers:?}");
    assert!(markers[0].starts_with("~~D8{"), "{}", markers[0]);
    assert!(markers[0].contains("\"min-api\":21"), "{}", markers[0]);
}

/// A stable name for what msec reported, to compare with the expectation table.
fn outcome_labels(container: &DexContainer) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    if let Some(error) = &container.error {
        labels.push(
            match error {
                DexError::NotDex => "not-dex",
                DexError::CompactDex => "compact-dex",
                DexError::UnsupportedVersion(_) => "unsupported-version",
                DexError::Truncated { .. } => "truncated",
                DexError::ByteSwapped => "byte-swapped",
                DexError::BadEndianTag(_) => "bad-endian-tag",
                DexError::BadHeaderSize { .. } => "bad-header-size",
                DexError::BadFileSize(_) => "bad-file-size",
                DexError::BadContainer(_) => "bad-container",
                DexError::TableOutOfBounds(table) => {
                    return vec![format!("table-out-of-bounds:{table}")];
                }
                other => panic!("unexpected {other:?}"),
            }
            .to_owned(),
        );
    }
    for file in &container.files {
        for anomaly in &file.anomalies {
            labels.push(match &anomaly.kind {
                DexAnomalyKind::ChecksumMismatch { .. } => "checksum".into(),
                DexAnomalyKind::SignatureMismatch => "signature".into(),
                DexAnomalyKind::TrailingData { .. } => "trailing-data".into(),
                DexAnomalyKind::InvalidMap(MapProblem::OutOfBounds) => "map-out-of-bounds".into(),
                DexAnomalyKind::InvalidMap(MapProblem::OutOfOrder) => "map-out-of-order".into(),
                DexAnomalyKind::InvalidMap(problem) => format!("map:{problem:?}"),
                DexAnomalyKind::TableOutOfBounds(table) => format!("table-out-of-bounds:{table}"),
                DexAnomalyKind::InvalidString { .. } => "invalid-string".into(),
                DexAnomalyKind::StringsOutOfOrder { .. } => "strings-out-of-order".into(),
                DexAnomalyKind::BadDescriptorIndex { .. } => "bad-descriptor-index".into(),
                DexAnomalyKind::BadClassIndex { .. } => "bad-class-index".into(),
                DexAnomalyKind::BadSuperclassIndex { .. } => "bad-superclass-index".into(),
                DexAnomalyKind::BadInterfaces { .. } => "bad-interfaces".into(),
                DexAnomalyKind::DuplicateClass { .. } => "duplicate-class".into(),
                DexAnomalyKind::StringBudgetExhausted { .. } => "string-budget".into(),
                DexAnomalyKind::InterfaceBudgetExhausted { .. } => "interface-budget".into(),
            });
        }
    }
    labels
}

/// What msec must report for each hostile file. Together with art-verdicts.txt this checks
/// both that msec finds the problem and that its claims about ART hold.
const EXPECTED: [(&str, &[&str]); 22] = [
    ("bad-checksum", &["checksum"]),
    ("bad-class-index", &["bad-class-index"]),
    ("bad-descriptor-index", &["bad-descriptor-index"]),
    ("bad-header-size", &["bad-header-size"]),
    ("bad-interfaces-offset", &["bad-interfaces"]),
    ("bad-signature", &["signature"]),
    ("bad-superclass-index", &["bad-superclass-index"]),
    ("byte-swapped", &["byte-swapped"]),
    ("compact-dex", &["compact-dex"]),
    (
        "container-table-in-later-section",
        &["table-out-of-bounds:class_defs"],
    ),
    ("duplicate-class", &["duplicate-class"]),
    ("invalid-mutf8", &["invalid-string"]),
    ("map-out-of-bounds", &["map-out-of-bounds"]),
    ("map-out-of-order", &["map-out-of-order"]),
    (
        "method-ids-out-of-bounds",
        &["table-out-of-bounds:method_ids"],
    ),
    (
        "string-amplification",
        &["strings-out-of-order", "string-budget"],
    ),
    (
        "string-ids-out-of-bounds",
        &["table-out-of-bounds:string_ids"],
    ),
    ("trailing-data", &["trailing-data"]),
    ("truncated", &["truncated"]),
    (
        "type-list-amplification",
        &["bad-interfaces", "duplicate-class", "interface-budget"],
    ),
    ("unsorted-strings", &["strings-out-of-order"]),
    ("version-036", &["unsupported-version"]),
];

#[test]
fn hostile_files_are_reported_and_art_agrees() {
    let verdicts = std::fs::read_to_string(dex_dir().join("art-verdicts.txt")).unwrap();
    let verdicts: BTreeMap<&str, bool> = verdicts
        .lines()
        .map(|line| {
            let (file, verdict) = line.split_once(": ").unwrap();
            (
                file.trim_end_matches(".dex"),
                verdict.starts_with("rejected"),
            )
        })
        .collect();
    let on_disk: Vec<String> = std::fs::read_dir(dex_dir().join("hostile"))
        .unwrap()
        .map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.trim_end_matches(".dex").to_owned()
        })
        .collect();
    assert_eq!(
        on_disk.len(),
        EXPECTED.len(),
        "every hostile file has an expectation"
    );

    for (name, expected) in EXPECTED {
        let container = parse(&read(&format!("hostile/{name}.dex")));
        let labels = outcome_labels(&container);
        assert_eq!(labels, expected, "{name}");

        let art_rejects = verdicts[name];
        let msec_claims_rejection = container
            .error
            .as_ref()
            .is_some_and(DexError::rejected_by_android)
            || container
                .files
                .iter()
                .flat_map(|file| &file.anomalies)
                .any(|anomaly| anomaly.kind.rejected_by_android());
        // dexdump verifies checksums, which msec reports without claiming every load does.
        let checksum_only = labels == ["checksum"];
        assert_eq!(
            msec_claims_rejection || checksum_only,
            art_rejects,
            "{name}: msec {labels:?}, ART rejects: {art_rejects}"
        );
    }
}

/// Files that share bytes cost at most about their own size to read, and say they were cut
/// short.
#[test]
fn amplification_is_bounded_and_reported() {
    let strings = parse(&read("hostile/string-amplification.dex"));
    let file = &strings.files[0];
    assert!(!strings.complete());
    // Four copies of the 30,000-character string fit in the budget (twice the file's 62 KB);
    // the fifth does not.
    assert!(file.anomalies.iter().any(|anomaly| matches!(
        anomaly.kind,
        DexAnomalyKind::StringBudgetExhausted { first_unread: 4 }
    )));
    assert_eq!(file.string_count(), 8_000);
    assert_eq!(file.strings().flatten().count(), 4);

    let lists = parse(&read("hostile/type-list-amplification.dex"));
    assert!(!lists.complete());
    assert_eq!(lists.files[0].classes.len(), 2_000);
}

#[test]
fn byte_edits_and_truncations_never_panic() {
    let original = read("v035.dex");
    for length in 0..original.len() {
        parse(&original[..length]);
    }
    for position in 0..original.len() {
        let mut edited = original.clone();
        edited[position] ^= 0xFF;
        parse(&edited);
    }
}

#[test]
fn an_apk_reads_its_dex_files_in_load_order() {
    let mut archive = ZipArchive::open(std::io::Cursor::new(CODE_APK), Limits::default()).unwrap();
    let apk = Apk::read(&mut archive);
    let paths: Vec<&str> = apk
        .dex_files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(paths, ["classes.dex", "classes2.dex"]);
    assert!(apk.dex_files.iter().all(|entry| entry.container.complete()));

    let summary = apk.code_summary();
    assert!(summary.complete);
    assert_eq!(summary.logical_files, 2);
    // Nine classes in classes.dex; Analytics and a second Config in classes2.dex.
    assert_eq!(summary.classes, 10);
    assert_eq!(
        summary.shadowed,
        [ShadowedClass {
            descriptor: "Ldev/appchk/fixture/code/Config;".into(),
            loaded_from: "classes.dex".into(),
            shadowed_in: "classes2.dex".into(),
        }]
    );
    assert_eq!(summary.shadowed_count, 1);
    assert_eq!(
        summary.packages,
        [
            PackageCount {
                package: "dev.appchk.fixture.code".into(),
                classes: 8,
            },
            PackageCount {
                package: String::new(),
                classes: 1,
            },
            PackageCount {
                package: "dev.appchk.fixture.code.extra".into(),
                classes: 1,
            },
        ]
    );
    let method_references: u64 = apk
        .dex_files
        .iter()
        .flat_map(|entry| &entry.container.files)
        .map(|file| u64::from(file.header.method_ids.count))
        .sum();
    assert_eq!(summary.method_references, method_references);
}

/// Inputs fuzzing found crashing (`fuzz/`), kept as regressions: a version 041 container whose
/// second section has a version 035 header, which was sized against the whole buffer instead
/// of what follows it, so its checksum range ran past the end.
#[test]
fn fuzz_regressions() {
    let old_version_section = include_bytes!("fixtures/fuzz/dex-container-old-version-section.bin");
    let container = parse(old_version_section);
    assert_eq!(container.files.len(), 1);
    assert!(matches!(container.error, Some(DexError::BadContainer(_))));
}
