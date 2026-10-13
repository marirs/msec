//! Signing checks (MobSF `cert_analysis.py::cert_info`), plus checks MobSF cannot make because
//! it does not verify signatures.

use super::{Origin, Severity};
use crate::android::signing::crypto::Hash;
use crate::android::signing::{Rejection, SigningReport};

/// Janus (CVE-2017-13156) affects Android 5.0-8.0; the fix shipped with Android 8.1.
const JANUS_FIXED_IN: u32 = 27;
/// APK Signature Scheme v2 is verified from Android 7.0.
const V2_VERIFIED_FROM: u32 = 24;
/// Android 11: apps targeting it need a v2 or later signature to install.
const V2_REQUIRED_FOR_TARGET: u32 = 30;
/// Smallest RSA key considered adequate.
const MIN_RSA_BITS: u32 = 2048;

/// A signing rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningRule {
    /// Signed (MobSF info).
    SignedApplication,
    /// No signature at all.
    MissingSignature,
    /// v1 is the only signature and the app installs on Android 8.0 or lower (Janus).
    JanusV1Only,
    /// v1 plus v2/v3, but the app installs on Android 6.0 or lower, which only checks v1.
    JanusOlderReleases,
    /// Signed with the Android SDK debug certificate.
    DebugCertificate,
    /// The signer certificate is signed with SHA-1.
    CertificateSha1,
    /// The signer certificate is signed with MD5.
    CertificateMd5,
    /// msec: a present signature does not verify (the APK was modified after signing).
    SignatureInvalid,
    /// msec: some Android release the app installs on has no signature it can verify, or
    /// sees a stripped signature.
    RejectedOnSomeReleases,
    /// msec: RSA key below 2048 bits.
    WeakKey,
    /// msec: only a v1 signature while targeting Android 11 or later: Android 11+ refuses to
    /// install it.
    V1OnlyTargetingAndroid11,
    /// msec: the signer certificate's validity has ended (Android does not check this; app
    /// stores and some tools do).
    CertificateExpired,
}

impl SigningRule {
    /// Engine key: MobSF finding titles as snake case; `msec_` for msec checks.
    pub fn key(self) -> &'static str {
        match self {
            Self::SignedApplication => "signed_application",
            Self::MissingSignature => "missing_signature",
            Self::JanusV1Only => "janus_vulnerability",
            Self::JanusOlderReleases => "janus_vulnerability_older_releases",
            Self::DebugCertificate => "debug_certificate",
            Self::CertificateSha1 => "certificate_sha1",
            Self::CertificateMd5 => "certificate_md5",
            Self::SignatureInvalid => "msec_signature_invalid",
            Self::RejectedOnSomeReleases => "msec_signature_rejected_on_some_releases",
            Self::WeakKey => "msec_weak_signing_key",
            Self::V1OnlyTargetingAndroid11 => "msec_v1_only_targeting_android_11",
            Self::CertificateExpired => "msec_certificate_expired",
        }
    }

    /// Where the rule comes from.
    pub fn origin(self) -> Origin {
        match self {
            Self::SignatureInvalid
            | Self::RejectedOnSomeReleases
            | Self::WeakKey
            | Self::V1OnlyTargetingAndroid11
            | Self::CertificateExpired => Origin::Msec,
            _ => Origin::MobSf,
        }
    }

    /// MobSF's scale.
    pub fn severity(self, sha256_manifest: bool) -> Severity {
        match self {
            Self::SignedApplication | Self::CertificateExpired => Severity::Info,
            Self::JanusOlderReleases | Self::WeakKey => Severity::Warning,
            Self::CertificateSha1 if sha256_manifest => Severity::Warning,
            _ => Severity::High,
        }
    }
}

/// One signing finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningFinding {
    /// The rule.
    pub rule: SigningRule,
    /// MobSF's severity for this finding.
    pub severity: Severity,
    /// What triggered it (scheme, certificate subject, key size, API range).
    pub detail: Option<String>,
}

/// Runs the signing checks for an app installable from `min_sdk` and targeting `target_sdk`.
/// `today` is `yyyy-MM-dd`.
pub fn analyse_signing(
    report: &SigningReport,
    min_sdk: u32,
    target_sdk: u32,
    today: &str,
) -> Vec<SigningFinding> {
    let sha256_manifest = report
        .v1
        .as_ref()
        .is_some_and(|jar| jar.entry_digests.contains(&Hash::Sha256));
    let mut findings = Vec::new();
    let mut add = |rule: SigningRule, detail: Option<String>| {
        findings.push(SigningFinding {
            rule,
            severity: rule.severity(sha256_manifest),
            detail,
        });
    };
    if !report.is_signed() {
        add(SigningRule::MissingSignature, None);
        return findings;
    }
    add(
        SigningRule::SignedApplication,
        Some(schemes_present(report)),
    );
    janus(report, min_sdk, &mut add);
    verification(report, min_sdk, target_sdk, &mut add);
    for certificate in report.certificates() {
        if certificate.is_debug() {
            add(
                SigningRule::DebugCertificate,
                Some(certificate.subject.clone()),
            );
        }
        match certificate.hash_algorithm {
            Some("sha1") => add(
                SigningRule::CertificateSha1,
                Some(certificate.signature_algorithm.clone()),
            ),
            Some("md5" | "md2") => add(
                SigningRule::CertificateMd5,
                Some(certificate.signature_algorithm.clone()),
            ),
            _ => {}
        }
        if certificate.public_key.algorithm == "RSA"
            && certificate
                .public_key
                .bits
                .is_some_and(|bits| bits < MIN_RSA_BITS)
        {
            add(
                SigningRule::WeakKey,
                certificate
                    .public_key
                    .bits
                    .map(|bits| format!("RSA {bits}-bit")),
            );
        }
        if certificate.has_expired(today) {
            add(
                SigningRule::CertificateExpired,
                Some(certificate.not_after.clone()),
            );
        }
    }
    let has_v2_or_later = report.schemes().next().is_some();
    if !has_v2_or_later && target_sdk >= V2_REQUIRED_FOR_TARGET {
        add(
            SigningRule::V1OnlyTargetingAndroid11,
            Some(target_sdk.to_string()),
        );
    }
    findings
}

fn schemes_present(report: &SigningReport) -> String {
    let mut schemes: Vec<&str> = Vec::new();
    if report.v1.is_some() {
        schemes.push("v1");
    }
    schemes.extend(report.schemes().map(|scheme| scheme.scheme.label()));
    schemes.join(", ")
}

/// MobSF flags v1 + v2/v3 at any minimum below Android 8.1 and v1 + v2/v3 at or above it as
/// high; msec follows what Janus actually needs (see `docs/PORTING.md`).
fn janus(report: &SigningReport, min_sdk: u32, add: &mut impl FnMut(SigningRule, Option<String>)) {
    if report.v1.is_none() {
        return;
    }
    let only_v1 = report.schemes().next().is_none();
    if only_v1 && min_sdk < JANUS_FIXED_IN {
        add(
            SigningRule::JanusV1Only,
            Some(format!("minSdkVersion {min_sdk}")),
        );
    } else if !only_v1 && min_sdk < V2_VERIFIED_FROM {
        add(
            SigningRule::JanusOlderReleases,
            Some(format!("minSdkVersion {min_sdk}")),
        );
    }
}

fn verification(
    report: &SigningReport,
    min_sdk: u32,
    target_sdk: u32,
    add: &mut impl FnMut(SigningRule, Option<String>),
) {
    let mut broken: Vec<&str> = Vec::new();
    if report.v1.as_ref().is_some_and(|jar| !jar.verified()) {
        broken.push("v1");
    }
    broken.extend(
        report
            .schemes()
            .filter(|scheme| !scheme.verified())
            .map(|scheme| scheme.scheme.label()),
    );
    if !broken.is_empty() {
        add(SigningRule::SignatureInvalid, Some(broken.join(", ")));
    }
    // Broken signatures and v1-only targeting Android 11+ have their own rules; this one is
    // for releases left without a usable signature or seeing a stripped one.
    let rejected = merged_ranges(
        report
            .platform_verdicts(min_sdk, target_sdk)
            .iter()
            .filter(|verdict| {
                matches!(
                    verdict.rejection,
                    Some(Rejection::NoSignature | Rejection::Stripped)
                )
            })
            .map(|verdict| (verdict.from_api, verdict.to_api)),
    );
    if !rejected.is_empty() && broken.is_empty() {
        add(
            SigningRule::RejectedOnSomeReleases,
            Some(rejected.join(", ")),
        );
    }
}

/// Adjacent API ranges joined: `28-29` and `30+` read `API 28+`.
fn merged_ranges(ranges: impl Iterator<Item = (u32, Option<u32>)>) -> Vec<String> {
    let mut merged: Vec<(u32, Option<u32>)> = Vec::new();
    for (from, to) in ranges {
        match merged.last_mut() {
            Some((_, end)) if end.is_some_and(|end| end + 1 == from) => *end = to,
            _ => merged.push((from, to)),
        }
    }
    merged
        .into_iter()
        .map(|(from, to)| match to {
            Some(to) => format!("API {from}-{to}"),
            None => format!("API {from}+"),
        })
        .collect()
}
