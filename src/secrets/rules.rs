//! The secret detectors and their compiled form.
//!
//! - MobSF's 22 known secret formats (`StaticAnalyzer/views/common/secret_detection.py`,
//!   `KNOWN_SECRET_PATTERNS`). MobSF writes them with look-behind and look-ahead, which the
//!   `regex` crate does not have; each is ported as the pattern without them plus the two
//!   character classes they excluded, checked around every match ([`MobsfPattern`]). Every
//!   pattern's last quantified class is the class its look-ahead excluded (or a fixed
//!   length), so a match the check rejects has no shorter match at the same start that Python
//!   would have accepted: the results are the same.
//! - gitleaks' default rules (`config/gitleaks.toml`, generated into
//!   [`super::generated::gitleaks`]), applied as gitleaks applies them: keywords prefilter a
//!   fragment, the secret is the rule's secret group (else the first non-empty group), and
//!   allowlists, `gitleaks:allow` lines and an entropy floor drop the rest, and a generic
//!   rule's finding gives way to a specific rule's on the same line. gitleaks writes RE2
//!   syntax, which `regex` accepts once the braces RE2 reads as literals are escaped (by the
//!   generator); patterns are compiled without Unicode classes, as RE2's `\w`, `\s` and `\b`
//!   are ASCII. Deferred: gitleaks' recursive decoding of Base64, hexadecimal and
//!   percent-encoded text (`--max-decode-depth`) is not ported yet; encoded secrets are found
//!   only when a format matches the encoded form.
//! - MobSF's key-name heuristic (`shared_func.py::is_secret_key`) and Shannon-entropy
//!   heuristic (`entropy.py`).
//!
//! Which findings are credentials, which are keys made to ship inside apps, and which are only
//! possible secrets is decided here by rule ([`class_of_gitleaks_rule`]), never by the
//! generated data.

use std::sync::LazyLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::{Regex, RegexBuilder};

use super::SecretClass;
use super::generated::gitleaks;

/// Compiled programs may be large: some rules repeat a class up to 2043 times.
const REGEX_SIZE_LIMIT: usize = 1 << 27;

/// gitleaks: whether every criterion of an allowlist must hold, or any one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Condition {
    /// Any criterion allows the finding (gitleaks' default, `OR`).
    Any,
    /// Every criterion given must hold (`AND`).
    All,
}

/// gitleaks: what an allowlist's regexes are matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// The secret (the default).
    Secret,
    /// The whole match.
    Match,
    /// The line the match is on.
    Line,
}

/// gitleaks' `[[rules.allowlists]]` and `[allowlist]`.
#[derive(Debug)]
pub(crate) struct Allowlist {
    pub(crate) condition: Condition,
    pub(crate) target: Target,
    pub(crate) regexes: &'static [&'static str],
    pub(crate) stopwords: &'static [&'static str],
    pub(crate) paths: &'static [&'static str],
}

/// gitleaks' `[[rules]]`.
#[derive(Debug)]
pub(crate) struct GitleaksRule {
    pub(crate) id: &'static str,
    pub(crate) description: &'static str,
    /// `None` for rules that match a file's path only (`pkcs12-file`).
    pub(crate) regex: Option<&'static str>,
    /// Files the rule applies to; with no regex, a file whose path matches is the finding.
    pub(crate) path: Option<&'static str>,
    /// The capture group holding the secret; 0 for the first non-empty group.
    pub(crate) secret_group: usize,
    /// Findings whose secret has this Shannon entropy or less are dropped.
    pub(crate) entropy: Option<f64>,
    /// Lower-case words one of which a fragment must contain for the rule to run.
    pub(crate) keywords: &'static [&'static str],
    pub(crate) allowlists: &'static [Allowlist],
}

/// One of MobSF's known secret formats, without its look-around.
struct MobsfPattern {
    name: &'static str,
    /// Characters that may not precede a match (MobSF's look-behind); empty for none.
    not_before: &'static str,
    pattern: &'static str,
    /// Characters that may not follow a match (MobSF's look-ahead).
    not_after: &'static str,
    /// Literals one of which every match contains, for the prefilter.
    keywords: &'static [&'static str],
}

const ALNUM: &str = "A-Za-z0-9";

/// MobSF v4.5.3 `KNOWN_SECRET_PATTERNS`, in MobSF's order. The OpenAI alternatives list the
/// 74-character form before the 58-character one: Python's backtracking tries 58 first and
/// falls back to 74 when the look-ahead fails, which a leftmost-first engine reproduces by
/// trying the longer form first.
static MOBSF_PATTERNS: [MobsfPattern; 22] = [
    MobsfPattern {
        name: "GitHub token",
        not_before: "A-Za-z0-9_",
        pattern: r"gh[pousr]_[A-Za-z0-9]{36,255}",
        not_after: ALNUM,
        keywords: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
    },
    MobsfPattern {
        name: "GitHub fine-grained token",
        not_before: "A-Za-z0-9_",
        pattern: r"github_pat_[A-Za-z0-9_]{20,255}",
        not_after: "A-Za-z0-9_",
        keywords: &["github_pat_"],
    },
    MobsfPattern {
        name: "GitLab personal access token",
        not_before: "A-Za-z0-9_-",
        pattern: r"glpat-[A-Za-z0-9_-]{20,255}",
        not_after: "A-Za-z0-9_-",
        keywords: &["glpat-"],
    },
    MobsfPattern {
        name: "Slack token",
        not_before: "A-Za-z0-9-",
        pattern: r"xox[baprs]-[A-Za-z0-9-]{10,255}",
        not_after: "A-Za-z0-9-",
        keywords: &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
    },
    MobsfPattern {
        name: "Slack webhook",
        not_before: "",
        pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,64}",
        not_after: ALNUM,
        keywords: &["hooks.slack.com"],
    },
    MobsfPattern {
        name: "Stripe live secret key",
        not_before: "A-Za-z0-9_",
        pattern: r"(?:sk|rk)_live_[A-Za-z0-9]{16,255}",
        not_after: ALNUM,
        keywords: &["sk_live_", "rk_live_"],
    },
    MobsfPattern {
        name: "SendGrid API key",
        not_before: "A-Za-z0-9_.-",
        pattern: r"SG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,128}",
        not_after: "A-Za-z0-9_-",
        keywords: &["sg."],
    },
    MobsfPattern {
        name: "npm access token",
        not_before: "A-Za-z0-9_",
        pattern: r"npm_[A-Za-z0-9]{36,64}",
        not_after: ALNUM,
        keywords: &["npm_"],
    },
    MobsfPattern {
        name: "Mapbox secret token",
        not_before: "A-Za-z0-9_.-",
        pattern: r"sk\.[A-Za-z0-9_-]{20,256}\.[A-Za-z0-9_-]{20,256}",
        not_after: "A-Za-z0-9_-",
        keywords: &["sk."],
    },
    MobsfPattern {
        name: "Anthropic API key",
        not_before: "A-Za-z0-9_-",
        pattern: r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA",
        not_after: "A-Za-z0-9_-",
        keywords: &["sk-ant-"],
    },
    MobsfPattern {
        name: "OpenAI API key",
        not_before: "A-Za-z0-9_-",
        pattern: concat!(
            r"(?:sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ",
            r"(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})",
            r"|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})"
        ),
        not_after: "A-Za-z0-9_-",
        keywords: &["t3blbkfj"],
    },
    MobsfPattern {
        name: "Hugging Face access token",
        not_before: "A-Za-z0-9_",
        pattern: r"hf_[A-Za-z]{34}",
        not_after: ALNUM,
        keywords: &["hf_"],
    },
    MobsfPattern {
        name: "DigitalOcean token",
        not_before: "A-Za-z0-9_",
        pattern: r"(?:doo|dop|dor)_v1_[a-f0-9]{64}",
        not_after: ALNUM,
        keywords: &["_v1_"],
    },
    MobsfPattern {
        name: "Doppler API token",
        not_before: "A-Za-z0-9_.",
        pattern: r"dp\.pt\.[A-Za-z0-9]{43}",
        not_after: ALNUM,
        keywords: &["dp.pt."],
    },
    MobsfPattern {
        name: "Brevo API token",
        not_before: "A-Za-z0-9_-",
        pattern: r"xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}",
        not_after: ALNUM,
        keywords: &["xkeysib-"],
    },
    MobsfPattern {
        name: "Sentry user token",
        not_before: "A-Za-z0-9_",
        pattern: r"sntryu_[a-f0-9]{64}",
        not_after: ALNUM,
        keywords: &["sntryu_"],
    },
    MobsfPattern {
        name: "Shopify access token",
        not_before: "A-Za-z0-9_",
        pattern: r"(?:shpat|shpca|shppa|shpss)_[A-Fa-f0-9]{32}",
        not_after: "A-Fa-f0-9",
        keywords: &["shpat_", "shpca_", "shppa_", "shpss_"],
    },
    MobsfPattern {
        name: "Square access token",
        not_before: "A-Za-z0-9_-",
        pattern: r"sq0atp-[A-Za-z0-9_-]{22,60}",
        not_after: "A-Za-z0-9_-",
        keywords: &["sq0atp-"],
    },
    MobsfPattern {
        name: "Private key",
        not_before: "",
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        not_after: "",
        keywords: &["-----begin"],
    },
    MobsfPattern {
        name: "Amazon LWA client secret",
        not_before: "A-Za-z0-9_.-",
        pattern: r"amzn1\.oa2-cs\.v[0-9]+\.[0-9A-Fa-f]{32,128}",
        not_after: "0-9A-Fa-f",
        keywords: &["amzn1.oa2-cs.v"],
    },
    MobsfPattern {
        name: "Amazon LWA access token",
        not_before: "A-Za-z0-9_-",
        pattern: r"Atza\|[A-Za-z0-9_-]{20,2043}",
        not_after: "A-Za-z0-9_-",
        keywords: &["atza|"],
    },
    MobsfPattern {
        name: "Amazon LWA refresh token",
        not_before: "A-Za-z0-9_-",
        pattern: r"Atzr\|[A-Za-z0-9_-]{20,2043}",
        not_after: "A-Za-z0-9_-",
        keywords: &["atzr|"],
    },
];

/// gitleaks rules whose matches are made to be embedded in client apps (public or
/// publishable keys, client and application identifiers): restricting them is the defence,
/// not keeping them secret.
const CLIENT_KEY_RULES: [&str; 21] = [
    "adobe-client-id",
    "algolia-api-key",
    "asana-client-id",
    "bitbucket-client-id",
    "contentful-delivery-api-token",
    "discord-client-id",
    "flutterwave-public-key",
    "gcp-api-key",
    "gitlab-feature-flag-client-token",
    "linkedin-client-id",
    "lob-pub-api-key",
    "looker-client-id",
    "mailgun-pub-key",
    "mapbox-api-token",
    "messagebird-client-id",
    "new-relic-browser-api-token",
    "new-relic-user-api-id",
    "plaid-client-id",
    "sendbird-access-id",
    "sumologic-access-id",
    "twitter-api-key",
];

/// gitleaks rules that only suggest a secret: generic assignments, JSON Web Tokens (often
/// public anonymous tokens) and test keys.
const POSSIBLE_RULES: [&str; 4] = [
    "easypost-test-api-token",
    "generic-api-key",
    "jwt",
    "jwt-base64",
];

/// How a gitleaks rule's findings are classified.
pub(crate) fn class_of_gitleaks_rule(id: &str) -> SecretClass {
    if CLIENT_KEY_RULES.contains(&id) {
        SecretClass::ClientKey
    } else if POSSIBLE_RULES.contains(&id) {
        SecretClass::Possible
    } else {
        SecretClass::Credential
    }
}

/// A known-format match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnownMatch {
    pub(crate) detector: KnownDetector,
    /// Byte range of the secret in the fragment.
    pub(crate) secret: (usize, usize),
    /// Byte range of the whole match (what a scrub removes).
    pub(crate) whole: (usize, usize),
}

/// Which known-format detector matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownDetector {
    Mobsf(&'static str),
    Gitleaks(&'static str),
}

struct CompiledMobsf {
    pattern: &'static MobsfPattern,
    regex: Regex,
    not_before: Option<Regex>,
    not_after: Option<Regex>,
}

struct CompiledAllowlist {
    list: &'static Allowlist,
    regexes: Vec<Regex>,
    paths: Vec<Regex>,
    stopwords: Vec<String>,
}

struct CompiledGitleaks {
    rule: &'static GitleaksRule,
    regex: Option<Regex>,
    path: Option<Regex>,
    allowlists: Vec<CompiledAllowlist>,
}

/// Everything compiled once per process.
struct Detectors {
    mobsf: Vec<CompiledMobsf>,
    gitleaks: Vec<CompiledGitleaks>,
    global: CompiledAllowlist,
    /// Every keyword of every detector; the value is the list of detectors it enables
    /// (MobSF patterns first, then gitleaks rules, as indexes).
    keywords: AhoCorasick,
    keyword_owners: Vec<Vec<usize>>,
    /// Detectors without keywords run on every fragment.
    unconditional: Vec<usize>,
}

fn compile(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .unwrap_or_else(|error| panic!("secret pattern {pattern:?} does not compile: {error}"))
}

fn compile_allowlist(list: &'static Allowlist) -> CompiledAllowlist {
    CompiledAllowlist {
        list,
        regexes: list
            .regexes
            .iter()
            .map(|pattern| compile(pattern))
            .collect(),
        paths: list.paths.iter().map(|pattern| compile(pattern)).collect(),
        stopwords: list
            .stopwords
            .iter()
            .map(|word| word.to_ascii_lowercase())
            .collect(),
    }
}

static DETECTORS: LazyLock<Detectors> = LazyLock::new(|| {
    let mobsf: Vec<CompiledMobsf> = MOBSF_PATTERNS
        .iter()
        .map(|pattern| CompiledMobsf {
            pattern,
            regex: compile(pattern.pattern),
            not_before: (!pattern.not_before.is_empty())
                .then(|| compile(&format!("^[{}]$", pattern.not_before))),
            not_after: (!pattern.not_after.is_empty())
                .then(|| compile(&format!("^[{}]$", pattern.not_after))),
        })
        .collect();
    let gitleaks: Vec<CompiledGitleaks> = gitleaks::RULES
        .iter()
        .map(|rule| CompiledGitleaks {
            rule,
            regex: rule.regex.map(compile),
            path: rule.path.map(compile),
            allowlists: rule.allowlists.iter().map(compile_allowlist).collect(),
        })
        .collect();
    let mut words: Vec<String> = Vec::new();
    let mut keyword_owners: Vec<Vec<usize>> = Vec::new();
    let mut unconditional = Vec::new();
    let keyword_lists = mobsf
        .iter()
        .map(|compiled| compiled.pattern.keywords)
        .chain(gitleaks.iter().map(|compiled| compiled.rule.keywords));
    for (detector, keywords) in keyword_lists.enumerate() {
        if keywords.is_empty() {
            unconditional.push(detector);
        }
        for keyword in keywords {
            let keyword = keyword.to_ascii_lowercase();
            match words.iter().position(|word| *word == keyword) {
                Some(position) => keyword_owners[position].push(detector),
                None => {
                    words.push(keyword);
                    keyword_owners.push(vec![detector]);
                }
            }
        }
    }
    let keywords = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard)
        .build(&words)
        .expect("the keyword automaton builds");
    Detectors {
        mobsf,
        gitleaks,
        global: compile_allowlist(&gitleaks::GLOBAL_ALLOWLIST),
        keywords,
        keyword_owners,
        unconditional,
    }
});

/// The gitleaks release the rules come from.
pub(crate) fn gitleaks_version() -> &'static str {
    gitleaks::VERSION
}

/// Description of a gitleaks rule.
pub(crate) fn gitleaks_description(id: &str) -> Option<&'static str> {
    gitleaks::RULES
        .iter()
        .find(|rule| rule.id == id)
        .map(|rule| rule.description)
}

/// Every known-format secret in `fragment`, a value or a whole text file at `path`. Matches
/// are in detector order (MobSF's patterns, then gitleaks' rules), each detector's in text
/// order.
pub(crate) fn known_formats(fragment: &str, path: &str) -> Vec<KnownMatch> {
    let detectors = &*DETECTORS;
    let bytes = fragment.as_bytes();
    let enabled = enabled_detectors(detectors, bytes);
    let mut found = Vec::new();
    for (index, compiled) in detectors.mobsf.iter().enumerate() {
        if enabled[index] {
            mobsf_matches(compiled, bytes, &mut found);
        }
    }
    if globally_allowed_path(detectors, path) {
        return found;
    }
    let mut gitleaks_found = Vec::new();
    for (offset, compiled) in detectors.gitleaks.iter().enumerate() {
        if enabled[detectors.mobsf.len() + offset] {
            gitleaks_matches(detectors, compiled, bytes, path, &mut gitleaks_found);
        }
    }
    found.extend(drop_superseded_generic(bytes, gitleaks_found));
    found
}

/// gitleaks' `filter`: a finding of a generic rule is dropped when a specific rule's finding on
/// the same line has a secret that contains it.
fn drop_superseded_generic(bytes: &[u8], found: Vec<KnownMatch>) -> Vec<KnownMatch> {
    let generic = |found: &KnownMatch| match found.detector {
        KnownDetector::Gitleaks(id) => id.contains("generic"),
        KnownDetector::Mobsf(_) => false,
    };
    let line_of = |found: &KnownMatch| {
        bytes[..found.whole.0]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count()
    };
    let secret = |found: &KnownMatch| &bytes[found.secret.0..found.secret.1];
    found
        .iter()
        .filter(|candidate| {
            !generic(candidate)
                || !found.iter().any(|other| {
                    !generic(other)
                        && other.detector != candidate.detector
                        && line_of(other) == line_of(candidate)
                        && contains(secret(other), secret(candidate))
                })
        })
        .cloned()
        .collect()
}

/// gitleaks rules that match a file by its path alone (`pkcs12-file`).
pub(crate) fn path_rules(path: &str) -> Vec<&'static str> {
    let detectors = &*DETECTORS;
    if globally_allowed_path(detectors, path) {
        return Vec::new();
    }
    detectors
        .gitleaks
        .iter()
        .filter(|compiled| compiled.regex.is_none())
        .filter(|compiled| {
            compiled
                .path
                .as_ref()
                .is_some_and(|regex| regex.is_match(path.as_bytes()))
        })
        .map(|compiled| compiled.rule.id)
        .collect()
}

fn globally_allowed_path(detectors: &Detectors, path: &str) -> bool {
    detectors
        .global
        .paths
        .iter()
        .any(|regex| regex.is_match(path.as_bytes()))
}

/// Which detectors may match: those whose keyword the fragment contains, and those without
/// keywords.
fn enabled_detectors(detectors: &Detectors, bytes: &[u8]) -> Vec<bool> {
    let mut enabled = vec![false; detectors.mobsf.len() + detectors.gitleaks.len()];
    for &detector in &detectors.unconditional {
        enabled[detector] = true;
    }
    for found in detectors.keywords.find_overlapping_iter(bytes) {
        for &detector in &detectors.keyword_owners[found.pattern().as_usize()] {
            enabled[detector] = true;
        }
    }
    enabled
}

/// MobSF's `finditer` with its look-around: a match whose neighbours fall in an excluded class
/// is rejected and the search resumes one byte later, as a failed look-behind or look-ahead
/// would make Python's engine do.
fn mobsf_matches(compiled: &CompiledMobsf, bytes: &[u8], found: &mut Vec<KnownMatch>) {
    let excluded = |class: &Option<Regex>, byte: Option<&u8>| match (class, byte) {
        (Some(class), Some(byte)) => class.is_match(std::slice::from_ref(byte)),
        _ => false,
    };
    let mut position = 0;
    while position <= bytes.len() {
        let Some(candidate) = compiled.regex.find_at(bytes, position) else {
            break;
        };
        let (start, end) = (candidate.start(), candidate.end());
        let before = start.checked_sub(1).and_then(|at| bytes.get(at));
        if excluded(&compiled.not_before, before) || excluded(&compiled.not_after, bytes.get(end)) {
            position = start + 1;
            continue;
        }
        found.push(KnownMatch {
            detector: KnownDetector::Mobsf(compiled.pattern.name),
            secret: (start, end),
            whole: (start, end),
        });
        position = if end > start { end } else { end + 1 };
    }
}

fn gitleaks_matches(
    detectors: &Detectors,
    compiled: &CompiledGitleaks,
    bytes: &[u8],
    path: &str,
    found: &mut Vec<KnownMatch>,
) {
    let Some(regex) = &compiled.regex else {
        return;
    };
    if let Some(only) = &compiled.path
        && !only.is_match(path.as_bytes())
    {
        return;
    }
    for captures in regex.captures_iter(bytes) {
        let whole = captures.get(0).expect("group 0 always matches");
        let secret = if compiled.rule.secret_group > 0 {
            captures.get(compiled.rule.secret_group)
        } else {
            (1..captures.len())
                .filter_map(|group| captures.get(group))
                .find(|group| !group.is_empty())
        }
        .unwrap_or(whole);
        let secret_bytes = &bytes[secret.start()..secret.end()];
        // gitleaks skips any finding on a line marked `gitleaks:allow`.
        if contains(line_around(bytes, whole.start()), b"gitleaks:allow") {
            continue;
        }
        if allowed(
            &detectors.global,
            secret_bytes,
            whole.as_bytes(),
            bytes,
            whole.start(),
            path,
        ) || compiled.allowlists.iter().any(|list| {
            allowed(
                list,
                secret_bytes,
                whole.as_bytes(),
                bytes,
                whole.start(),
                path,
            )
        }) {
            continue;
        }
        if let Some(floor) = compiled.rule.entropy
            && shannon_entropy(secret_bytes) <= floor
        {
            continue;
        }
        found.push(KnownMatch {
            detector: KnownDetector::Gitleaks(compiled.rule.id),
            secret: (secret.start(), secret.end()),
            whole: (whole.start(), whole.end()),
        });
    }
}

/// gitleaks' allowlist check: with `Any`, one criterion that holds allows the finding; with
/// `All`, every criterion the list gives must hold.
fn allowed(
    list: &CompiledAllowlist,
    secret: &[u8],
    whole: &[u8],
    fragment: &[u8],
    at: usize,
    path: &str,
) -> bool {
    let target = match list.list.target {
        Target::Secret => secret,
        Target::Match => whole,
        Target::Line => line_around(fragment, at),
    };
    let lowered = String::from_utf8_lossy(secret).to_ascii_lowercase();
    let criteria = [
        (!list.regexes.is_empty()).then(|| list.regexes.iter().any(|regex| regex.is_match(target))),
        (!list.stopwords.is_empty()).then(|| {
            list.stopwords
                .iter()
                .any(|word| lowered.contains(word.as_str()))
        }),
        (!list.paths.is_empty()).then(|| {
            list.paths
                .iter()
                .any(|regex| regex.is_match(path.as_bytes()))
        }),
    ];
    let mut given = criteria.iter().flatten().peekable();
    if given.peek().is_none() {
        return false;
    }
    match list.list.condition {
        Condition::Any => criteria.iter().flatten().any(|held| *held),
        Condition::All => criteria.iter().flatten().all(|held| *held),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The line of `fragment` holding byte `at`.
fn line_around(fragment: &[u8], at: usize) -> &[u8] {
    let start = fragment[..at]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let end = fragment[at..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(fragment.len(), |newline| at + newline);
    &fragment[start..end]
}

/// gitleaks' Shannon entropy: over the characters present, by byte length.
pub(crate) fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let text = String::from_utf8_lossy(data);
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for character in text.chars() {
        *counts.entry(character).or_default() += 1;
    }
    let length = data.len() as f64;
    counts
        .values()
        .map(|&count| {
            let frequency = count as f64 / length;
            -frequency * frequency.log2()
        })
        .sum()
}

/// MobSF `is_secret_key`: a key named like a credential, and not like a UI label.
///
/// Departs from MobSF on purpose: MobSF's "contains" list has `'certificate"'` with a stray
/// quote, which no key can contain; msec checks `certificate` (PORTING.md deviation 34).
pub fn is_secret_key(key: &str) -> bool {
    const ENDS_WITH: [&str; 11] = [
        "api",
        "key",
        "secret",
        "token",
        "username",
        "user_name",
        "user",
        "pass",
        "password",
        "private_key",
        "access_key",
    ];
    const CONTAINS: [&str; 23] = [
        "api_",
        "key_",
        "aws",
        "s3_",
        "_s3",
        "secret_",
        "bearer",
        "jwt",
        "certificate",
        "credential",
        "azure",
        "webhook",
        "twilio_",
        "bitcoin",
        "_auth",
        "firebase",
        "oauth",
        "authorization",
        "private",
        "pwd",
        "session",
        "token_",
        "gcp",
    ];
    const NOT_CONTAINS: [&str; 33] = [
        "label_",
        "text",
        "hint",
        "msg_",
        "create_",
        "message",
        "new",
        "confirm",
        "activity_",
        "forgot",
        "dashboard_",
        "current_",
        "signup",
        "sign_in",
        "signin",
        "title_",
        "welcome_",
        "change_",
        "this_",
        "the_",
        "placeholder",
        "invalid_",
        "btn_",
        "action_",
        "prompt_",
        "lable",
        "hide_",
        "old",
        "update",
        "error",
        "empty",
        "txt_",
        "lbl_",
    ];
    let key = key.to_lowercase();
    let excluded = NOT_CONTAINS.iter().any(|word| key.contains(word));
    let named = ENDS_WITH.iter().any(|word| key.ends_with(word))
        || CONTAINS.iter().any(|word| key.contains(word));
    named && !excluded
}

/// MobSF `entropy.py`: runs of 20 or more Base64 or hexadecimal characters whose entropy over
/// that alphabet passes MobSF's thresholds, in strings of 21 characters or more, without class
/// paths, alphabet runs, paths and purely alphabetic runs.
pub(crate) fn high_entropy_runs(text: &str) -> Vec<String> {
    static BASE64: LazyLock<Regex> = LazyLock::new(|| compile(r"[a-zA-Z0-9+/=]{20,}"));
    static HEX: LazyLock<Regex> = LazyLock::new(|| compile(r"[a-fA-F0-9-]{20,}"));
    const BASE64_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    const HEX_ALPHABET: &str = "1234567890abcdefABCDEF";
    if text.chars().count() < 21 {
        return Vec::new();
    }
    let mut runs = Vec::new();
    for (regex, alphabet, threshold) in
        [(&*BASE64, BASE64_ALPHABET, 4.5), (&*HEX, HEX_ALPHABET, 3.0)]
    {
        for found in regex.find_iter(text.as_bytes()) {
            let run = String::from_utf8_lossy(found.as_bytes()).into_owned();
            if alphabet_entropy(&run, alphabet) > threshold && !mobsf_excluded(&run) {
                runs.push(run);
            }
        }
    }
    runs
}

/// MobSF `entropy.entropy`: entropy over the characters of `alphabet` only, by the run's
/// length.
fn alphabet_entropy(run: &str, alphabet: &str) -> f64 {
    let length = run.chars().count() as f64;
    alphabet
        .chars()
        .map(|character| run.chars().filter(|&c| c == character).count() as f64 / length)
        .filter(|&probability| probability > 0.0)
        .map(|probability| -probability * probability.log2())
        .sum()
}

/// MobSF `entropy.exclude`.
fn mobsf_excluded(run: &str) -> bool {
    let lowered = run.to_lowercase();
    (run.starts_with('L') && run.contains('/'))
        || lowered.contains("abcdefghi")
        || lowered.contains("kotlin/")
        || run.matches('/').count() > 1
        || run.chars().all(char::is_alphabetic)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value built from pieces, so no complete token appears in the source.
    fn token(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn every_detector_compiles() {
        let detectors = &*DETECTORS;
        assert_eq!(detectors.mobsf.len(), 22);
        assert!(
            detectors.gitleaks.len() >= 200,
            "{}",
            detectors.gitleaks.len()
        );
    }

    #[test]
    fn mobsf_look_around_is_kept() {
        let github = token(&["gh", "p_", &"a1B2".repeat(9)]);
        let names = |text: &str| -> Vec<&'static str> {
            known_formats(text, "x")
                .into_iter()
                .filter_map(|found| match found.detector {
                    KnownDetector::Mobsf(name) => Some(name),
                    KnownDetector::Gitleaks(_) => None,
                })
                .collect()
        };
        assert_eq!(names(&github), ["GitHub token"]);
        assert_eq!(names(&format!("\"{github}\"")), ["GitHub token"]);
        // A word character before it, or one more alphanumeric past 255, rejects it.
        assert_eq!(names(&format!("x{github}")), Vec::<&str>::new());
        assert_eq!(
            names(&token(&["gh", "p_", &"a".repeat(256)])),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn gitleaks_allowlists_and_entropy_apply() {
        let found = |text: &str| -> Vec<&'static str> {
            known_formats(text, "assets/config.json")
                .into_iter()
                .filter_map(|found| match found.detector {
                    KnownDetector::Gitleaks(id) => Some(id),
                    KnownDetector::Mobsf(_) => None,
                })
                .collect()
        };
        let aws = token(&["AKIA", "Z2X7Q5L3MBN4K6PJ"]);
        assert_eq!(found(&aws), ["aws-access-token"]);
        // gitleaks allows AWS's documented example key.
        assert_eq!(
            found(&token(&["AKIA", "IOSFODNN7", "EXAMPLE"])),
            Vec::<&str>::new()
        );
        // Too little entropy.
        assert_eq!(
            found(&token(&["AKIA", "AAAAAAAAAAAAAAAA"])),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn key_names_follow_mobsf() {
        assert!(is_secret_key("google_api_key"));
        assert!(is_secret_key("aws_secret"));
        assert!(is_secret_key("server_certificate"));
        assert!(!is_secret_key("hint_password"));
        assert!(!is_secret_key("app_name"));
    }

    #[test]
    fn entropy_follows_mobsf() {
        assert_eq!(
            high_entropy_runs("Zx81Kq0Lm2Pw9Rt5Yv3Bn7Hc4Gd6Fs1A"),
            ["Zx81Kq0Lm2Pw9Rt5Yv3Bn7Hc4Gd6Fs1A"]
        );
        assert!(high_entropy_runs("Lcom/example/app/MainActivity;xx").is_empty());
        assert!(high_entropy_runs("short").is_empty());
    }
}
