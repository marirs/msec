//! Hardcoded secrets in an app package: credentials (MobSF's known formats and gitleaks'
//! rules), API keys made to ship in apps, and values MobSF's heuristics flag as possible
//! secrets (a key named like a credential, a high-entropy string).
//!
//! Ports MobSF's `secret_detection.py`, `entropy.py`, `shared_func.py::is_secret_key` and the
//! string sources of `android/strings.py`, `ios/strings.py` and `ios/plist_analysis.py`, and
//! adds gitleaks' rule set (MIT; see `rules.rs`) and text files MobSF does not read (assets,
//! raw resources, bundle resources). The strings come from [`crate::package_strings`]; what each
//! source gets:
//!
//! | Source | Detectors |
//! |---|---|
//! | resource strings | known formats; key name (default configuration) |
//! | DEX strings that pass MobSF's code-string filter | known formats; entropy |
//! | native libraries' and executables' strings | known formats; entropy |
//! | property list values | known formats; key name |
//! | text files | known formats |
//!
//! Secrets never leave this module in full: a finding carries a redacted form (a public
//! prefix such as `ghp_`, and for credentials and client keys the last four characters) and
//! the length. A secret's location and context (resource name, class, plist key, line) are
//! what a reader needs to find and rotate it.

mod generated;
pub(crate) mod rules;

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

pub use rules::is_secret_key;
use rules::{KnownDetector, class_of_gitleaks_rule};

use crate::package_strings::{PackageString, Source, Visitor};

/// Every known-format detector that matches `text` (a value, or a whole file at `path`), in
/// detector order: MobSF's patterns, then gitleaks' rules; once per match. The building block
/// of the scans, public so tools and tests can check single values.
pub fn detect(text: &str, path: &str) -> Vec<Detector> {
    rules::known_formats(text, path)
        .into_iter()
        .map(|found| classify(found.detector).1)
        .collect()
}

/// MobSF's entropy heuristic on one string: the high-entropy runs it reports.
pub fn entropy_runs(text: &str) -> Vec<String> {
    rules::high_entropy_runs(text)
}

/// Possible-secret findings kept per scan; heuristics on a large app can flag thousands of
/// strings, and the rest are counted ([`SecretScan::possible_not_listed`]).
const MAX_POSSIBLE_FINDINGS: usize = 500;

/// What a secret is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecretClass {
    /// A credential for a service: whoever extracts it can act as the app's owner.
    Credential,
    /// A key or identifier made to be embedded in apps (a Google API key, a publishable key):
    /// not secret, but abuse is limited only by the restrictions set on it.
    ClientKey,
    /// What MobSF's heuristics flag: a value under a key named like a secret, or a
    /// high-entropy string. Often benign.
    Possible,
}

impl SecretClass {
    /// `credential`, `client_key`, `possible`.
    pub fn key(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::ClientKey => "client_key",
            Self::Possible => "possible",
        }
    }
}

/// How a secret was recognised.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Detector {
    /// One of MobSF's known formats, by name (`GitHub token`).
    Mobsf(&'static str),
    /// A gitleaks rule, by ID (`aws-access-token`).
    Gitleaks(&'static str),
    /// MobSF's key-name heuristic: a value without spaces under a key named like a secret.
    KeyName,
    /// MobSF's entropy heuristic.
    Entropy,
}

impl Detector {
    /// What it found, for a reader: `GitHub token`, gitleaks' description, ...
    pub fn label(&self) -> String {
        match self {
            Self::Mobsf(name) => (*name).to_owned(),
            Self::Gitleaks(id) => {
                rules::gitleaks_description(id).map_or_else(|| (*id).to_owned(), str::to_owned)
            }
            Self::KeyName => "value of a key named like a secret".to_owned(),
            Self::Entropy => "high-entropy string".to_owned(),
        }
    }

    /// `mobsf`, `gitleaks`, `key_name`, `entropy`.
    pub fn origin(&self) -> &'static str {
        match self {
            Self::Mobsf(_) => "mobsf",
            Self::Gitleaks(_) => "gitleaks",
            Self::KeyName => "key_name",
            Self::Entropy => "entropy",
        }
    }

    /// The rule within its origin (`GitHub token`, `aws-access-token`); `None` for the
    /// heuristics.
    pub fn rule(&self) -> Option<&'static str> {
        match self {
            Self::Mobsf(name) => Some(name),
            Self::Gitleaks(id) => Some(id),
            Self::KeyName | Self::Entropy => None,
        }
    }
}

impl fmt::Display for Detector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rule() {
            Some(rule) => write!(formatter, "{}:{rule}", self.origin()),
            None => formatter.write_str(self.origin()),
        }
    }
}

/// One secret, where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFinding {
    /// What it is.
    pub class: SecretClass,
    /// What recognised it (the most specific detector, when several did).
    pub detector: Detector,
    /// The file in the package (`classes.dex`, `resources.arsc`, `Payload/A.app/Info.plist`).
    pub location: String,
    /// Where in the file: `@string/api_key`, a class (`com.example.Config`), a plist key path
    /// (`Keys/API_KEY`), `line 12`.
    pub context: Option<String>,
    /// The value with all but a public prefix (and, for credentials and client keys, the last
    /// four characters) hidden: `ghp_…3fQ1`, `••••`.
    pub redacted: String,
    /// Its length in characters.
    pub length: usize,
}

/// A file that was not read for secrets, and why.
pub use crate::package_strings::Unread as Skipped;

/// How much was read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceCounts {
    /// Resource string values.
    pub resource_strings: usize,
    /// DEX strings that are not identifiers.
    pub code_strings: usize,
    /// Strings from native libraries and executables.
    pub binary_strings: usize,
    /// Property lists.
    pub property_lists: usize,
    /// Other text files.
    pub text_files: usize,
}

/// Every secret found in a package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretScan {
    /// Findings, credentials first, then client keys, then possible secrets, each in the order
    /// found.
    pub findings: Vec<SecretFinding>,
    /// What was read.
    pub counts: SourceCounts,
    /// Files not read (too large, unreadable, the text budget spent).
    pub skipped: Vec<Skipped>,
    /// Possible-secret findings beyond the first 500, counted only.
    pub possible_not_listed: usize,
    /// The gitleaks release whose rules ran.
    pub gitleaks_version: &'static str,
}

impl SecretScan {
    /// Every file that should have been read was read.
    pub fn complete(&self) -> bool {
        self.skipped.is_empty()
    }
}

/// What to run on a value besides the known formats.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ValueChecks<'a> {
    /// The key it is stored under, for MobSF's key-name heuristic.
    pub(crate) key: Option<&'a str>,
    /// Run MobSF's entropy heuristic.
    pub(crate) entropy: bool,
}

/// Collects findings, once per (location, context, value), keeping the most severe class.
pub(crate) struct Collector {
    scan: SecretScan,
    /// Position in `scan.findings` of each (location, context, value hash).
    seen: HashMap<(String, Option<String>, u64), usize>,
    possible: usize,
}

impl Collector {
    pub(crate) fn new() -> Self {
        Self {
            scan: SecretScan {
                gitleaks_version: rules::gitleaks_version(),
                ..SecretScan::default()
            },
            seen: HashMap::new(),
            possible: 0,
        }
    }

    /// Known formats, then the heuristics asked for, on one value.
    pub(crate) fn value(
        &mut self,
        location: &str,
        context: Option<&str>,
        value: &str,
        checks: ValueChecks<'_>,
    ) {
        let known = rules::known_formats(value, location);
        for found in &known {
            let secret = byte_range(value, found.secret);
            let (class, detector) = classify(found.detector);
            self.record(class, detector, location, context, &secret);
        }
        if let Some(key) = checks.key
            && !value.is_empty()
            && !value.contains(' ')
            && is_secret_key(key)
        {
            self.record(
                SecretClass::Possible,
                Detector::KeyName,
                location,
                context,
                value,
            );
        }
        if checks.entropy {
            // MobSF removes known-format secrets before looking for high-entropy strings, so
            // one secret is not reported twice.
            let scrubbed = scrub(value, &known);
            for run in rules::high_entropy_runs(&scrubbed) {
                self.record(
                    SecretClass::Possible,
                    Detector::Entropy,
                    location,
                    context,
                    &run,
                );
            }
        }
    }

    /// Known formats in a whole text file, each with its line.
    pub(crate) fn text_file(&mut self, location: &str, text: &str) {
        self.scan.counts.text_files += 1;
        for found in rules::known_formats(text, location) {
            let line = 1 + text.as_bytes()[..found.whole.0]
                .iter()
                .filter(|&&byte| byte == b'\n')
                .count();
            let secret = byte_range(text, found.secret);
            let (class, detector) = classify(found.detector);
            self.record(
                class,
                detector,
                location,
                Some(&format!("line {line}")),
                &secret,
            );
        }
    }

    /// gitleaks rules that flag a file by its name (a PKCS #12 key store).
    pub(crate) fn file_name(&mut self, location: &str) {
        for id in rules::path_rules(location) {
            self.record(
                class_of_gitleaks_rule(id),
                Detector::Gitleaks(id),
                location,
                None,
                "",
            );
        }
    }

    fn record(
        &mut self,
        class: SecretClass,
        detector: Detector,
        location: &str,
        context: Option<&str>,
        secret: &str,
    ) {
        let mut hasher = DefaultHasher::new();
        secret.hash(&mut hasher);
        let key = (
            location.to_owned(),
            context.map(str::to_owned),
            hasher.finish(),
        );
        if let Some(&position) = self.seen.get(&key) {
            let existing = &mut self.scan.findings[position];
            if class < existing.class {
                existing.class = class;
                existing.detector = detector;
                existing.redacted = redact(class, secret);
            }
            return;
        }
        if class == SecretClass::Possible {
            if self.possible >= MAX_POSSIBLE_FINDINGS {
                self.scan.possible_not_listed += 1;
                return;
            }
            self.possible += 1;
        }
        self.seen.insert(key, self.scan.findings.len());
        self.scan.findings.push(SecretFinding {
            class,
            detector,
            location: location.to_owned(),
            context: context.map(str::to_owned),
            redacted: redact(class, secret),
            length: secret.chars().count(),
        });
    }

    pub(crate) fn finish(mut self) -> SecretScan {
        // Stable: within a class, findings stay in the order they were found.
        self.scan.findings.sort_by_key(|finding| finding.class);
        self.scan
    }
}

/// MobSF's filter on code strings (`shared_func.py::strings_and_entropies`): at least four
/// characters, starting with a letter or digit, not an escaped NUL or a `com.google.` name,
/// and not a JVM or Android path.
fn mobsf_code_string(text: &str) -> bool {
    text.chars().count() >= 4
        && text.chars().next().is_some_and(char::is_alphanumeric)
        && !text.contains("\\u0")
        && !text.contains("com.google.")
        && !(text.contains('/')
            && ["Ljava", "Lkotlin", "kotlin", "android"]
                .iter()
                .any(|word| text.contains(word)))
}

impl Visitor for Collector {
    fn string(&mut self, string: &PackageString<'_>) {
        let checks = match string.source {
            Source::Resource => {
                self.scan.counts.resource_strings += 1;
                ValueChecks {
                    key: string.key,
                    entropy: false,
                }
            }
            Source::Code => {
                if !mobsf_code_string(string.text) {
                    return;
                }
                self.scan.counts.code_strings += 1;
                ValueChecks {
                    key: None,
                    entropy: true,
                }
            }
            Source::Binary => {
                self.scan.counts.binary_strings += 1;
                ValueChecks {
                    key: None,
                    entropy: true,
                }
            }
            Source::PropertyList => ValueChecks {
                key: string.key,
                entropy: false,
            },
        };
        self.value(string.location, string.context, string.text, checks);
    }

    fn text_file(&mut self, location: &str, text: &str) {
        Collector::text_file(self, location, text);
    }

    fn property_list(&mut self, _location: &str) {
        self.scan.counts.property_lists += 1;
    }

    fn file(&mut self, path: &str) {
        self.file_name(path);
    }

    fn skipped(&mut self, path: &str, reason: &str) {
        self.scan.skipped.push(Skipped {
            path: path.to_owned(),
            reason: reason.to_owned(),
        });
    }
}

/// Secrets in APKs and app bundles.
pub mod android {
    use std::io::{Read, Seek};

    use super::{Collector, SecretScan};
    use crate::android::{Apk, Bundle};
    use crate::archive::ZipArchive;
    use crate::package_strings::android::{walk_apk, walk_bundle};

    /// Secrets in an APK.
    pub fn scan_apk<R: Read + Seek>(archive: &mut ZipArchive<R>, apk: &Apk) -> SecretScan {
        let mut collector = Collector::new();
        walk_apk(archive, apk, &mut collector);
        collector.finish()
    }

    /// Secrets in an app bundle, module by module.
    pub fn scan_bundle<R: Read + Seek>(archive: &mut ZipArchive<R>, bundle: &Bundle) -> SecretScan {
        let mut collector = Collector::new();
        walk_bundle(archive, bundle, &mut collector);
        collector.finish()
    }
}

/// Secrets in IPAs.
pub mod ios {
    use std::io::{Read, Seek};

    use super::{Collector, SecretScan};
    use crate::archive::ZipArchive;
    use crate::ios::Ipa;
    use crate::package_strings::ios::walk_ipa;

    /// Secrets in the IPA's app bundle; an empty scan without one.
    pub fn scan_ipa<R: Read + Seek>(archive: &mut ZipArchive<R>, ipa: &Ipa) -> SecretScan {
        let mut collector = Collector::new();
        walk_ipa(archive, ipa, &mut collector);
        collector.finish()
    }
}

fn classify(detector: KnownDetector) -> (SecretClass, Detector) {
    match detector {
        KnownDetector::Mobsf(name) => (SecretClass::Credential, Detector::Mobsf(name)),
        KnownDetector::Gitleaks(id) => (class_of_gitleaks_rule(id), Detector::Gitleaks(id)),
    }
}

/// The bytes of a match as text. Patterns run on bytes without Unicode classes (as RE2's do),
/// so a match may start or end inside a multi-byte character; slicing the `str` there would
/// panic, so the bytes are converted lossily instead.
fn byte_range(text: &str, (start, end): (usize, usize)) -> String {
    String::from_utf8_lossy(&text.as_bytes()[start..end]).into_owned()
}

/// `value` with every known-format match removed (MobSF `pattern.sub('', ...)`).
fn scrub(value: &str, known: &[rules::KnownMatch]) -> String {
    if known.is_empty() {
        return value.to_owned();
    }
    let bytes = value.as_bytes();
    let mut ranges: Vec<(usize, usize)> = known.iter().map(|found| found.whole).collect();
    ranges.sort_unstable();
    let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut position = 0;
    for (start, end) in ranges {
        if start > position {
            kept.extend_from_slice(&bytes[position..start]);
        }
        position = position.max(end);
    }
    kept.extend_from_slice(&bytes[position.min(bytes.len())..]);
    String::from_utf8_lossy(&kept).into_owned()
}

/// Prefixes that name a token's kind rather than carry its secret, longest first where one
/// extends another.
const PUBLIC_PREFIXES: [&str; 58] = [
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "glptt-",
    "gldt-",
    "glrt-",
    "xoxe.xoxp-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "xapp-",
    "sk_live_",
    "rk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "sk-ant-api03-",
    "sk-ant-admin01-",
    "sk-proj-",
    "sk-svcacct-",
    "sk-admin-",
    "SG.",
    "npm_",
    "hf_",
    "api_org_",
    "doo_v1_",
    "dop_v1_",
    "dor_v1_",
    "dp.pt.",
    "xkeysib-",
    "sntryu_",
    "sntrys_",
    "shpat_",
    "shpca_",
    "shppa_",
    "shpss_",
    "sq0atp-",
    "sq0csp-",
    "amzn1.oa2-cs.v",
    "Atza|",
    "Atzr|",
    "AKIA",
    "ASIA",
    "ABIA",
    "ACCA",
    "AIza",
    "LTAI",
    "glc_",
    "dckr_pat_",
    "pypi-",
    "rubygems_",
    "https://hooks.slack.com/services/",
];

/// The redacted form of a secret: a PEM header is shown whole (it names the key type, not the
/// key); otherwise a public prefix, then for credentials and client keys of 20 characters or
/// more the last four characters, so the owner can tell which key to rotate.
fn redact(class: SecretClass, secret: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    if secret.starts_with("-----BEGIN") {
        let header_end = secret[5..]
            .find("-----")
            .map_or(secret.len(), |at| at + 10)
            .min(secret.len());
        return format!("{}…", &secret[..header_end]);
    }
    let prefix = PUBLIC_PREFIXES
        .iter()
        .filter(|prefix| secret.starts_with(**prefix))
        .max_by_key(|prefix| prefix.len())
        .copied()
        .unwrap_or("");
    let characters: Vec<char> = secret.chars().collect();
    if class != SecretClass::Possible && characters.len() >= 20 {
        let tail: String = characters[characters.len() - 4..].iter().collect();
        format!("{prefix}…{tail}")
    } else {
        format!("{prefix}••••")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobsf_code_string_filter() {
        assert!(mobsf_code_string("abcd"));
        assert!(!mobsf_code_string("abc"));
        assert!(!mobsf_code_string("_private"));
        assert!(!mobsf_code_string("com.google.android.gms"));
        assert!(!mobsf_code_string("Ljava/lang/String;"));
        assert!(mobsf_code_string("kotlin is fine without a slash"));
    }

    #[test]
    fn redaction_keeps_only_public_parts() {
        let github = ["gh", "p_", "Zx81Kq0Lm2Pw9Rt5Yv3Bn7Hc4Gd6Fs1A2B4"].concat();
        assert_eq!(redact(SecretClass::Credential, &github), "ghp_…A2B4");
        assert_eq!(
            redact(SecretClass::Possible, "hunter2hunter2hunter2"),
            "••••"
        );
        assert_eq!(
            redact(
                SecretClass::Credential,
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEow"
            ),
            "-----BEGIN RSA PRIVATE KEY-----…"
        );
        assert_eq!(redact(SecretClass::Credential, "short"), "••••");
    }

    #[test]
    fn one_value_one_finding_most_severe_class() {
        let mut collector = Collector::new();
        let key = ["AI", "za", "SyD8f2KxQ0wP4mN7vB1cR5tY9uL3hJ6gE2a"].concat();
        collector.value(
            "resources.arsc",
            Some("@string/google_api_key"),
            &key,
            ValueChecks {
                key: Some("google_api_key"),
                entropy: false,
            },
        );
        let scan = collector.finish();
        assert_eq!(scan.findings.len(), 1, "{:?}", scan.findings);
        assert_eq!(scan.findings[0].class, SecretClass::ClientKey);
        assert_eq!(scan.findings[0].detector, Detector::Gitleaks("gcp-api-key"));
        assert_eq!(scan.findings[0].redacted, "AIza…gE2a");
    }
}
