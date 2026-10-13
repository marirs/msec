//! Manifest and network security checks against aapt2-built fixtures. Expected findings follow
//! MobSF v4.5.3 `manifest_analysis.py` / `network_security.py`, except the deviations listed in
//! docs/PORTING.md (each one is pointed out where it shows).

use std::io::Cursor;

use msec::android::Apk;
use msec::android::analysis::network::Scope;
use msec::android::analysis::{NetworkRule, Origin, Severity};
use msec::archive::{Limits, ZipArchive};

const BASIC_APK: &[u8] = include_bytes!("fixtures/android/basic.apk");
const RISKY_APK: &[u8] = include_bytes!("fixtures/android/risky.apk");
const NETWORK_APK: &[u8] = include_bytes!("fixtures/android/network.apk");
const TODAY: &str = "2026-10-13";

fn apk(bytes: &[u8]) -> Apk {
    Apk::read(&mut ZipArchive::open(Cursor::new(bytes.to_vec()), Limits::default()).unwrap())
}

/// `(MobSF key, component without package, detail)` for each manifest finding.
fn manifest_summary(apk: &Apk) -> Vec<(String, String, String)> {
    let package = apk
        .manifest
        .as_ref()
        .and_then(|manifest| manifest.package.clone())
        .unwrap_or_default();
    apk.manifest_findings()
        .into_iter()
        .map(|finding| {
            let component = finding
                .component
                .map(|(_, name)| {
                    name.strip_prefix(&format!("{package}."))
                        .unwrap_or(&name)
                        .to_owned()
                })
                .unwrap_or_default();
            (
                finding.rule.mobsf_key().to_owned(),
                component,
                finding.detail.unwrap_or_default(),
            )
        })
        .collect()
}

fn expected(rows: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
    rows.iter()
        .map(|(key, component, detail)| ((*key).into(), (*component).into(), (*detail).into()))
        .collect()
}

#[test]
fn basic_app_findings() {
    assert_eq!(
        manifest_summary(&apk(BASIC_APK)),
        expected(&[
            ("vulnerable_os_version", "", "24"),
            ("has_network_security", "", "@xml/network_security_config"),
            ("app_is_debuggable", "", ""),
            ("app_allowbackup", "", ""),
            // The launcher activity is never reported as exported (MobSF only skips it when the
            // manifest names it fully qualified).
            ("exported_intent_filter_exists", "BootReceiver", ""),
            ("explicitly_exported", "DataProvider", ""),
        ])
    );
}

#[test]
fn risky_app_findings_cover_every_manifest_check_family() {
    assert_eq!(
        manifest_summary(&apk(RISKY_APK)),
        expected(&[
            ("vulnerable_os_version", "", "16"),
            ("direct_boot_aware", "", ""),
            ("allowbackup_not_set", "", ""),
            ("app_in_test_mode", "", ""),
            ("msec_cleartext_by_default", "", "22"),
            ("msec_user_certificates_trusted_by_default", "", "22"),
            ("task_hijacking2", "Main", "22"),
            ("task_affinity_set", "Hijackable", "com.example.other"),
            ("non_standard_launchmode", "Hijackable", ""),
            ("task_hijacking", "Hijackable", "22"),
            ("task_hijacking2", "Hijackable", "22"),
            ("explicitly_exported", "Hijackable", ""),
            ("exported_intent_filter_exists", "Links", ""),
            ("exported_protected_permission_normal", "OpenService", ""),
            (
                "exported_protected_permission_signature",
                "AdminService",
                ""
            ),
            // BIND_JOB_SERVICE is a framework signature permission; MobSF calls it undefined.
            ("exported_protected_permission_signature", "Jobs", ""),
            ("exported_protected_permission_not_defined", "Unknown", ""),
            ("exported_intent_filter_exists", "SecretCodes", ""),
            ("explicitly_exported", "BinarySms", ""),
            ("exported_provider_2", "Files", ""),
            ("improper_provider_permission", "Files", "pathPrefix=/"),
            ("dialer_code_found", "SecretCodes", "4636"),
            // Only the data SMS port; the https link's port 8443 is not an SMS port.
            ("sms_receiver_port_found", "BinarySms", "6734"),
            ("high_intent_priority_found", "", "999 (2 hits)"),
            ("msec_unverified_app_links", "Links", "risky.example.com"),
        ])
    );
}

#[test]
fn severities_and_origins_follow_mobsf() {
    let findings = apk(RISKY_APK).manifest_findings();
    let severity_of = |key: &str| {
        findings
            .iter()
            .find(|finding| finding.rule.mobsf_key() == key)
            .unwrap()
            .severity()
    };
    assert_eq!(severity_of("vulnerable_os_version"), Severity::High);
    assert_eq!(severity_of("task_hijacking"), Severity::High);
    assert_eq!(severity_of("explicitly_exported"), Severity::Warning);
    assert_eq!(
        severity_of("exported_protected_permission_signature"),
        Severity::Info
    );
    assert_eq!(severity_of("direct_boot_aware"), Severity::Info);
    let msec_rules: Vec<&str> = findings
        .iter()
        .filter(|finding| finding.rule.origin() == Origin::Msec)
        .map(|finding| finding.rule.mobsf_key())
        .collect();
    assert_eq!(
        msec_rules,
        [
            "msec_cleartext_by_default",
            "msec_user_certificates_trusted_by_default",
            "msec_unverified_app_links"
        ]
    );
}

#[test]
fn exported_components_carry_their_protecting_permission() {
    let findings = apk(RISKY_APK).manifest_findings();
    let permission_of = |component: &str| {
        findings
            .iter()
            .find(|finding| {
                finding
                    .component
                    .as_ref()
                    .is_some_and(|(_, name)| name.ends_with(component))
            })
            .and_then(|finding| finding.permission.clone())
    };
    assert_eq!(
        permission_of(".Jobs").as_deref(),
        Some("android.permission.BIND_JOB_SERVICE")
    );
    assert_eq!(permission_of(".Hijackable"), None);
}

#[test]
fn network_security_configuration_findings() {
    let apk = apk(NETWORK_APK);
    let config = apk
        .network_security_config
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap();
    assert_eq!(config.domains.len(), 2);
    assert_eq!(config.domains[1].domains[0].name, "legacy.api.example.com");
    // Nested domain configs inherit cleartext from their parent.
    assert_eq!(config.domains[1].policy.cleartext_permitted, Some(false));

    let summary: Vec<(NetworkRule, String, Option<String>, Severity)> = apk
        .network_findings(TODAY)
        .into_iter()
        .map(|finding| {
            let scope = match &finding.scope {
                Scope::Base => "*".to_owned(),
                Scope::Domains(domains) => domains.join(","),
                Scope::DebugOverrides => "debug".to_owned(),
            };
            let severity = finding.severity();
            (finding.rule, scope, finding.detail, severity)
        })
        .collect();
    let raw = Some("@raw/company_ca".to_owned());
    assert_eq!(
        summary,
        [
            (
                NetworkRule::CleartextPermitted,
                "*".into(),
                None,
                Severity::High
            ),
            (
                NetworkRule::TrustsSystemCertificates,
                "*".into(),
                None,
                Severity::Warning
            ),
            (
                NetworkRule::TrustsUserCertificates,
                "*".into(),
                None,
                Severity::High
            ),
            (NetworkRule::OverridesPins, "*".into(), None, Severity::High),
            (
                NetworkRule::CleartextBlocked,
                "api.example.com".into(),
                None,
                Severity::Secure
            ),
            (
                NetworkRule::TrustsBundledCertificates,
                "api.example.com".into(),
                raw.clone(),
                Severity::Info
            ),
            (
                NetworkRule::PinsExpired,
                "api.example.com".into(),
                Some("2024-01-01".into()),
                Severity::Warning
            ),
            (
                NetworkRule::CleartextBlocked,
                "legacy.api.example.com".into(),
                None,
                Severity::Secure
            ),
            (
                NetworkRule::CleartextPermitted,
                "debug".into(),
                None,
                Severity::High
            ),
            (
                NetworkRule::TrustsBundledCertificates,
                "debug".into(),
                raw,
                Severity::High
            ),
            (
                NetworkRule::OverridesPins,
                "debug".into(),
                None,
                Severity::High
            ),
        ]
    );
    let manifest = manifest_summary(&apk);
    assert!(manifest.contains(&(
        "has_network_security".into(),
        String::new(),
        "@xml/netsec".into()
    )));
}

#[test]
fn debug_overrides_are_ignored_in_release_builds() {
    let apk = apk(NETWORK_APK);
    let config = apk
        .network_security_config
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap();
    let release = msec::android::analysis::analyse_network_security(config, false, TODAY);
    assert!(
        release
            .iter()
            .all(|finding| finding.scope != Scope::DebugOverrides)
    );
}
