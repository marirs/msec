//! Secret detection against MobSF's and gitleaks' own verdicts (tests/fixtures/secrets, rebuilt
//! by build_secrets.py): every fixture value is checked by MobSF v4.5.3's detection code and by
//! gitleaks 8.30.1, and msec must report what each reports; then the fixture APK is scanned end
//! to end. The values are fake and stored masked (Base64 of the bytes XORed with 0x5A).

use std::collections::BTreeMap;
use std::path::Path;

use msec::android::Apk;
use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::secrets::{self, Detector, SecretClass, SecretFinding};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/secrets");
const PACKAGE: &str = "dev.appchk.fixture.secrets";
const NATIVE_LIBRARY: &str = "lib/arm64-v8a/libsecrets.so";
const BUNDLE: &str = "Payload/Fixture.app/";
const IOS_LIBRARY: &str = "Payload/Fixture.app/Frameworks/libsecrets.dylib";

struct Unit {
    name: String,
    placement: String,
    key: String,
    value: String,
}

fn read(name: &str) -> String {
    std::fs::read_to_string(Path::new(DIR).join(name)).unwrap()
}

fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for byte in text.bytes().filter(|&byte| byte != b'=') {
        let value = ALPHABET.iter().position(|&c| c == byte).unwrap() as u32;
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    out
}

/// build_secrets.py's `mask`, undone: Base64, then each byte XORed with 0x5A.
fn unmask(text: &str) -> String {
    String::from_utf8(base64(text).into_iter().map(|byte| byte ^ 0x5a).collect()).unwrap()
}

/// build_secrets.py's `mask`.
fn mask(text: &str) -> String {
    let masked: Vec<u8> = text.bytes().map(|byte| byte ^ 0x5a).collect();
    encode(&masked)
}

fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let group = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        for position in 0..4 {
            if position <= chunk.len() {
                out.push(ALPHABET[((group >> (18 - 6 * position)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn units() -> Vec<Unit> {
    read("units.txt")
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            Unit {
                name: fields[0].to_owned(),
                placement: fields[1].to_owned(),
                key: fields[2].to_owned(),
                value: unmask(fields[3]),
            }
        })
        .collect()
}

fn verdicts(name: &str) -> BTreeMap<String, Vec<String>> {
    read(name)
        .lines()
        .map(|line| {
            let mut fields = line.split('\t');
            let unit = fields.next().unwrap().to_owned();
            (unit, fields.map(str::to_owned).collect())
        })
        .collect()
}

fn field<'a>(fields: &'a [String], name: &str) -> &'a str {
    fields
        .iter()
        .find_map(|field| field.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} in {fields:?}"))
}

fn list(text: &str, separator: char) -> Vec<String> {
    let mut items: Vec<String> = text
        .split(separator)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect();
    items.sort();
    items
}

/// The key a value is stored under: a resource's name, or the last key of a plist key path
/// (`Config.plist:Endpoints/Payments`).
fn leaf_key(key: &str) -> &str {
    let path = key.rsplit_once(':').map_or(key, |(_, path)| path);
    path.rsplit_once('/').map_or(path, |(_, leaf)| leaf)
}

/// The path gitleaks saw the value at, which path-scoped rules and allowlists read.
fn gitleaks_path(unit: &Unit) -> String {
    if unit.placement == "file" {
        unit.key.clone()
    } else {
        format!("units/{}.txt", unit.name)
    }
}

#[test]
fn every_value_reads_as_mobsf_and_gitleaks_read_it() {
    let mobsf = verdicts("mobsf-verdicts.txt");
    let gitleaks = verdicts("gitleaks-verdicts.txt");
    let units = units();
    assert!(units.len() >= 30, "{}", units.len());
    for unit in &units {
        let detected = secrets::detect(&unit.value, &gitleaks_path(unit));
        let mut gitleaks_ids: Vec<String> = detected
            .iter()
            .filter_map(|detector| match detector {
                Detector::Gitleaks(id) => Some((*id).to_owned()),
                _ => None,
            })
            .collect();
        gitleaks_ids.sort();
        assert_eq!(
            gitleaks_ids,
            list(&gitleaks[&unit.name][0], ','),
            "{}: gitleaks",
            unit.name
        );
        let fields = &mobsf[&unit.name];
        if fields[0] == "filtered" {
            continue;
        }
        let mut mobsf_names: Vec<String> = detected
            .iter()
            .filter_map(|detector| match detector {
                Detector::Mobsf(name) => Some((*name).to_owned()),
                _ => None,
            })
            .collect();
        mobsf_names.sort();
        mobsf_names.dedup();
        assert_eq!(
            mobsf_names,
            list(field(fields, "known"), '|'),
            "{}: MobSF",
            unit.name
        );
        match field(fields, "key_name") {
            "-" => {}
            verdict => assert_eq!(
                secrets::is_secret_key(leaf_key(&unit.key)) && !unit.value.contains(' '),
                verdict == "yes",
                "{}: key name",
                unit.name
            ),
        }
        match field(fields, "entropy") {
            "-" => {}
            verdict => {
                let mut runs: Vec<String> = secrets::entropy_runs(&unit.value)
                    .iter()
                    .map(|run| mask(run))
                    .collect();
                runs.sort();
                runs.dedup();
                assert_eq!(runs, list(verdict, ','), "{}: entropy", unit.name);
            }
        }
    }
}

fn scan() -> msec::secrets::SecretScan {
    let mut archive =
        ZipArchive::open_path(Path::new(DIR).join("secrets.apk"), Limits::default()).unwrap();
    let apk = Apk::read(&mut archive);
    secrets::android::scan_apk(&mut archive, &apk)
}

fn camel(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut characters = part.chars();
            characters
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + characters.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// Where a unit's finding is: its file and context.
fn place(unit: &Unit) -> (String, Option<String>) {
    match unit.placement.as_str() {
        "resource" => (
            "resources.arsc".to_owned(),
            Some(format!("@string/{}", unit.key)),
        ),
        "code" => (
            "classes.dex".to_owned(),
            Some(format!("{PACKAGE}.{}", camel(&unit.name))),
        ),
        "static" => ("classes.dex".to_owned(), None),
        "native" => (NATIVE_LIBRARY.to_owned(), None),
        "plist" => {
            let (file, path) = unit.key.split_once(':').unwrap();
            (format!("{BUNDLE}{file}"), Some(path.to_owned()))
        }
        "macho" => (IOS_LIBRARY.to_owned(), None),
        _ => (unit.key.clone(), None),
    }
}

fn at<'a>(scan: &'a [SecretFinding], unit: &Unit) -> Vec<&'a SecretFinding> {
    let (location, context) = place(unit);
    scan.iter()
        .filter(|finding| {
            finding.location == location && (unit.placement == "file" || finding.context == context)
        })
        .collect()
}

/// No finding shows a secret: at most a public prefix and the last four characters, so the
/// eight characters before those four never appear.
fn assert_redacted(findings: &[SecretFinding], units: &[Unit]) {
    for unit in units.iter().filter(|unit| unit.placement != "file") {
        let length = unit.value.chars().count();
        if length < 28 {
            continue;
        }
        let middle: String = unit.value.chars().skip(length - 12).take(8).collect();
        for finding in findings {
            assert!(
                !finding.redacted.contains(&middle),
                "{} shows {}",
                finding.redacted,
                unit.name
            );
        }
    }
}

#[test]
fn the_fixture_apk_reports_every_secret_redacted() {
    let scan = scan();
    assert!(scan.complete(), "{:?}", scan.skipped);
    assert_eq!(scan.gitleaks_version, "v8.30.1");
    assert!(scan.counts.resource_strings >= 7 && scan.counts.code_strings >= 13);
    assert!(scan.counts.binary_strings >= 10 && scan.counts.text_files == 3);
    let mobsf = verdicts("mobsf-verdicts.txt");
    let gitleaks = verdicts("gitleaks-verdicts.txt");
    let units = units();
    for unit in &units {
        let found = at(&scan.findings, unit);
        let known = mobsf
            .get(&unit.name)
            .is_some_and(|fields| fields[0] != "filtered" && !field(fields, "known").is_empty())
            || !gitleaks[&unit.name][0].is_empty();
        let in_apk = !unit.name.starts_with("ios_") && !unit.key.starts_with(BUNDLE);
        if known && in_apk {
            assert!(!found.is_empty(), "{}: not found", unit.name);
        }
    }
    assert_redacted(&scan.findings, &units);
    let class_of = |name: &str| -> Vec<(SecretClass, String)> {
        let unit = units.iter().find(|unit| unit.name == name).unwrap();
        at(&scan.findings, unit)
            .into_iter()
            .map(|finding| (finding.class, finding.detector.to_string()))
            .collect()
    };
    assert_eq!(
        class_of("google_api_key"),
        [(SecretClass::ClientKey, "gitleaks:gcp-api-key".to_owned())]
    );
    assert_eq!(
        class_of("aws_secret"),
        [(SecretClass::Possible, "key_name".to_owned())]
    );
    assert_eq!(
        class_of("build_token"),
        [(SecretClass::Credential, "mobsf:GitHub token".to_owned())]
    );
    assert_eq!(
        class_of("aws_key_id"),
        [(
            SecretClass::Credential,
            "gitleaks:aws-access-token".to_owned()
        )]
    );
    assert_eq!(
        class_of("doppler"),
        [(
            SecretClass::Credential,
            "mobsf:Doppler API token".to_owned()
        )]
    );
    assert!(class_of("jwt").contains(&(SecretClass::Possible, "gitleaks:jwt".to_owned())));
    assert_eq!(
        class_of("entropy_hex"),
        [(SecretClass::Possible, "entropy".to_owned())]
    );
    for negative in ["hint_password", "app_name", "endpoint", "class_name"] {
        assert_eq!(class_of(negative), [], "{negative}");
    }
    // A PKCS #12 key store is flagged by its name; the reviewed line of config.json keeps
    // gitleaks quiet but not MobSF, which has no allow marker.
    assert!(
        scan.findings
            .iter()
            .any(|finding| finding.location == "assets/certs/client.p12"
                && finding.detector == Detector::Gitleaks("pkcs12-file"))
    );
    let config: Vec<String> = scan
        .findings
        .iter()
        .filter(|finding| finding.location == "assets/config.json")
        .map(|finding| {
            format!(
                "{} {}",
                finding.detector,
                finding.context.as_deref().unwrap_or("")
            )
        })
        .collect();
    assert!(
        config.contains(&"mobsf:GitHub token line 10".to_owned()),
        "{config:?}"
    );
    assert!(
        config.contains(&"gitleaks:heroku-api-key line 5".to_owned()),
        "{config:?}"
    );
    assert!(
        !config.iter().any(|line| line.contains("aws-access-token")),
        "{config:?}"
    );
}

#[test]
fn the_fixture_ipa_reports_every_secret_redacted() {
    let mut archive =
        ZipArchive::open_path(Path::new(DIR).join("secrets.ipa"), Limits::default()).unwrap();
    let ipa = Ipa::read(&mut archive);
    let scan = secrets::ios::scan_ipa(&mut archive, &ipa);
    assert!(scan.complete(), "{:?}", scan.skipped);
    assert!(scan.counts.property_lists >= 4 && scan.counts.binary_strings >= 5);
    let units = units();
    assert_redacted(&scan.findings, &units);
    let found = |name: &str| -> Vec<(SecretClass, String)> {
        let unit = units.iter().find(|unit| unit.name == name).unwrap();
        at(&scan.findings, unit)
            .into_iter()
            .map(|finding| (finding.class, finding.detector.to_string()))
            .collect()
    };
    assert_eq!(
        found("ios_google_api_key"),
        [(SecretClass::ClientKey, "gitleaks:gcp-api-key".to_owned())]
    );
    assert_eq!(
        found("ios_api_secret"),
        [(SecretClass::Possible, "key_name".to_owned())]
    );
    assert_eq!(
        found("ios_stripe"),
        [(
            SecretClass::Credential,
            "mobsf:Stripe live secret key".to_owned()
        )]
    );
    assert_eq!(
        found("ios_webhook"),
        [(SecretClass::Credential, "mobsf:Slack webhook".to_owned())]
    );
    for negative in ["ios_client_id", "ios_database", "ios_welcome"] {
        assert_eq!(found(negative), [], "{negative}");
    }
    let library: Vec<String> = scan
        .findings
        .iter()
        .filter(|finding| finding.location == IOS_LIBRARY)
        .map(|finding| finding.detector.to_string())
        .collect();
    for expected in [
        "mobsf:GitHub fine-grained token",
        "mobsf:GitLab personal access token",
        "mobsf:Hugging Face access token",
        "entropy",
    ] {
        assert!(library.contains(&expected.to_owned()), "{library:?}");
    }
    let json: Vec<String> = scan
        .findings
        .iter()
        .filter(|finding| finding.location == format!("{BUNDLE}config.json"))
        .map(|finding| finding.detector.to_string())
        .collect();
    assert_eq!(json, ["mobsf:GitHub token", "gitleaks:aws-access-token"]);
    // The fixture app itself (its executables, Info.plist, privacy manifests) holds no
    // credential or client key.
    let expected_locations = [
        format!("{BUNDLE}GoogleService-Info.plist"),
        format!("{BUNDLE}Config.plist"),
        format!("{BUNDLE}config.json"),
        IOS_LIBRARY.to_owned(),
    ];
    for finding in &scan.findings {
        if finding.class != SecretClass::Possible {
            assert!(
                expected_locations.contains(&finding.location),
                "{finding:?}"
            );
        }
    }
}
