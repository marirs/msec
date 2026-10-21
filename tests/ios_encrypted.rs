//! An App Store-encrypted executable (tests/fixtures/ios/build_encrypted.sh): the sections msec
//! reads that lie in the encrypted range are those otool places there (encrypted-verdicts.txt);
//! their contents are not read, every check that needed them is reported as unchecked, and
//! nothing is reported as a finding for want of reading them.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::ios::analysis::{BinaryRule, analyse_binaries};
use msec::ios::coverage::{UncheckedCause, UncheckedCheck, unchecked};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ios");

fn open(name: &str) -> (ZipArchive<Cursor<Vec<u8>>>, Ipa) {
    let bytes = std::fs::read(Path::new(FIXTURES).join("ipa").join(name)).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    let ipa = Ipa::read(&mut archive);
    (archive, ipa)
}

/// otool's reading, per executable: the encrypted range (when `cryptid` is set) and each
/// section's file range.
#[derive(Default)]
struct Reading {
    encrypted: Option<(u64, u64)>,
    sections: Vec<(String, u64, u64)>,
}

fn oracle() -> BTreeMap<String, Reading> {
    let text = std::fs::read_to_string(Path::new(FIXTURES).join("encrypted-verdicts.txt")).unwrap();
    let mut readings: BTreeMap<String, Reading> = BTreeMap::new();
    let mut current = String::new();
    let (mut offset, mut size) = (0, 0);
    for line in text.lines() {
        if let Some(binary) = line.strip_suffix(':') {
            current = binary.to_owned();
            readings.insert(current.clone(), Reading::default());
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let reading = readings.get_mut(&current).unwrap();
        match fields.as_slice() {
            ["cryptoff", value] => offset = value.parse().unwrap(),
            ["cryptsize", value] => size = value.parse().unwrap(),
            ["cryptid", value] => {
                reading.encrypted = (*value != "0").then_some((offset, offset + size));
            }
            [name, start, length] => reading.sections.push((
                (*name).to_owned(),
                start.parse().unwrap(),
                u64::from_str_radix(length.trim_start_matches("0x"), 16).unwrap(),
            )),
            _ => panic!("{line}"),
        }
    }
    readings
}

#[test]
fn encrypted_sections_are_those_otool_places_in_the_range() {
    let (_, ipa) = open("encrypted.ipa");
    let app = ipa.app.as_ref().unwrap();
    let readings = oracle();
    assert_eq!(readings.len(), 3);
    let mut encrypted_binaries = 0;
    for (relative, reading) in readings {
        let binary = app
            .binaries
            .iter()
            .find(|binary| binary.path == format!("{}{relative}", app.path))
            .unwrap_or_else(|| panic!("{relative}"));
        let mut expected: Vec<String> = reading
            .sections
            .iter()
            .filter(|(_, start, length)| {
                reading
                    .encrypted
                    .is_some_and(|(from, to)| *start < to && start + length > from)
            })
            .map(|(name, ..)| name.clone())
            .collect();
        expected.sort();
        assert_eq!(binary.encrypted_sections, expected, "{relative}");
        encrypted_binaries += usize::from(reading.encrypted.is_some());
    }
    assert_eq!(encrypted_binaries, 1);
}

/// Imports are read from the symbol table, which is not encrypted; selectors are not read.
#[test]
fn only_imported_apis_are_found_in_an_encrypted_executable() {
    let (_, plain) = open("privacy.ipa");
    let (_, encrypted) = open("encrypted.ipa");
    let main = |ipa: &Ipa| {
        ipa.app.as_ref().unwrap().binaries[0]
            .required_reason_apis
            .clone()
    };
    let plain_imports: Vec<_> = main(&plain)
        .into_iter()
        .filter(|api| !api.by_selector)
        .collect();
    assert!(main(&plain).iter().any(|api| api.by_selector));
    assert!(!plain_imports.is_empty());
    assert_eq!(main(&encrypted), plain_imports);
}

#[test]
fn what_encryption_hides_is_unchecked_not_clean() {
    let (_, ipa) = open("encrypted.ipa");
    let app = ipa.app.as_ref().unwrap();
    let main = &app.binaries[0];
    let parts: Vec<(UncheckedCheck, UncheckedCause, bool)> = unchecked(app)
        .iter()
        .filter(|part| part.cause == UncheckedCause::Encrypted)
        .map(|part| (part.check, part.cause, part.location == main.path))
        .collect();
    assert_eq!(
        parts,
        [
            (UncheckedCheck::PageHashes, UncheckedCause::Encrypted, true),
            (UncheckedCheck::Strings, UncheckedCause::Encrypted, true),
            (UncheckedCheck::MethodNames, UncheckedCause::Encrypted, true),
        ]
    );
    // The page hashes were not compared, so no mismatch is claimed.
    assert_eq!(main.signatures[0].pages, None);
    assert!(!analyse_binaries(app).iter().any(|finding| finding.rule
        == BinaryRule::SignatureMismatch
        && finding.binary == main.path));
    // The unencrypted original has nothing encrypted.
    let (_, plain) = open("privacy.ipa");
    assert!(
        unchecked(plain.app.as_ref().unwrap())
            .iter()
            .all(|part| part.cause != UncheckedCause::Encrypted)
    );
}

/// The secret and tracker scans name the encrypted executable as unread, by cause.
#[test]
fn string_scans_report_the_encrypted_executable() {
    let (mut archive, ipa) = open("encrypted.ipa");
    let main = ipa.app.as_ref().unwrap().binaries[0].path.clone();
    let secrets = msec::secrets::ios::scan_ipa(&mut archive, &ipa);
    let trackers = msec::trackers::scan_ipa(&mut archive, &ipa);
    for skipped in [&secrets.skipped, &trackers.skipped] {
        let encrypted: Vec<&str> = skipped
            .iter()
            .filter(|unread| unread.encrypted)
            .map(|unread| unread.path.as_str())
            .collect();
        assert_eq!(encrypted, [main.as_str()]);
    }
    let (mut archive, plain) = open("privacy.ipa");
    let secrets = msec::secrets::ios::scan_ipa(&mut archive, &plain);
    assert!(secrets.skipped.iter().all(|unread| !unread.encrypted));
}
