//! Backup rule files (tests/fixtures/android/build_backup.sh): the files the manifest names in
//! fullBackupContent and dataExtractionRules, read from an APK (binary XML) and from an app
//! bundle (protobuf XML) to the same rules, as aapt2's dump shows them.

use std::io::Cursor;

use msec::android::backup::{BackupMode, BackupPath, BackupRules, BackupRulesSource};
use msec::android::{Apk, Bundle};
use msec::archive::{Limits, ZipArchive};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/android");

fn archive(name: &str) -> ZipArchive<Cursor<Vec<u8>>> {
    let bytes = std::fs::read(format!("{FIXTURES}/{name}")).unwrap();
    ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap()
}

fn path(domain: &str, path: &str) -> BackupPath {
    BackupPath {
        domain: domain.to_owned(),
        path: path.to_owned(),
    }
}

fn expected() -> Vec<BackupRules> {
    vec![
        BackupRules {
            source: BackupRulesSource::FullBackupContent,
            path: "res/xml/backup_rules.xml".to_owned(),
            modes: vec![BackupMode {
                mode: "full-backup-content".to_owned(),
                requires_encryption: None,
                includes: vec![path("sharedpref", "."), path("database", "notes.db")],
                excludes: vec![path("sharedpref", "session.xml")],
            }],
        },
        BackupRules {
            source: BackupRulesSource::DataExtractionRules,
            path: "res/xml/data_extraction_rules.xml".to_owned(),
            modes: vec![
                BackupMode {
                    mode: "cloud-backup".to_owned(),
                    requires_encryption: Some(true),
                    includes: vec![],
                    excludes: vec![path("sharedpref", "session.xml"), path("file", "tokens/")],
                },
                BackupMode {
                    mode: "device-transfer".to_owned(),
                    requires_encryption: None,
                    includes: vec![],
                    excludes: vec![path("file", "tokens/")],
                },
            ],
        },
    ]
}

#[test]
fn rule_files_read_like_aapt2_dumps_them() {
    let dump = std::fs::read_to_string(format!("{FIXTURES}/backup/xmltree.txt")).unwrap();
    for line in [
        "A: domain=\"sharedpref\" (Raw: \"sharedpref\")",
        "A: path=\"session.xml\" (Raw: \"session.xml\")",
        "A: path=\"notes.db\" (Raw: \"notes.db\")",
        "A: disableIfNoEncryptionCapabilities=true",
        "A: path=\"tokens/\" (Raw: \"tokens/\")",
    ] {
        assert!(dump.contains(line), "{line}");
    }
    let apk = Apk::read(&mut archive("backup.apk"));
    let rules: Vec<BackupRules> = apk
        .backup_rules
        .into_iter()
        .map(|(source, rules)| {
            let rules = rules.unwrap();
            assert_eq!(rules.source, source);
            rules
        })
        .collect();
    assert_eq!(rules, expected());
}

#[test]
fn an_app_bundle_reads_the_same_rules() {
    let mut archive = archive("backup.aab");
    let mut bundle = Bundle::read(&mut archive);
    let base = bundle.base.take().unwrap();
    let rules: Vec<BackupRules> = base
        .backup_rules
        .into_iter()
        .map(|(_, rules)| rules.unwrap())
        .collect();
    assert_eq!(rules, expected());
}

/// An app that names no rule file has none; one whose attribute is a boolean has none to read.
#[test]
fn no_rule_files_named_none_read() {
    let apk = Apk::read(&mut archive("basic.apk"));
    assert!(apk.backup_rules.is_empty());
}
