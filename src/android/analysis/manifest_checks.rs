//! Manifest checks (MobSF `manifest_analysis.py`).

use super::{Origin, Severity};
use crate::android::manifest::{
    Application, Component, ComponentKind, IntentFilter, LaunchMode, Manifest,
};
use crate::android::permissions::framework_permission;

/// Android 4.2: providers stopped being exported by default.
const ANDROID_4_2: u32 = 17;
/// Android 5.0: the singleTask/singleInstance task-reuse issue was fixed.
const ANDROID_5_0: u32 = 21;
/// Android 7.0: apps stopped trusting user-installed CAs by default.
const ANDROID_7_0: u32 = 24;
/// MobSF: a minimum below Android 8.0 reaches unpatched releases (high).
const ANDROID_8_0: u32 = 26;
/// Android 9: cleartext traffic blocked by default; StrandHogg fixed for targeting apps.
const ANDROID_9: u32 = 28;
/// MobSF: a minimum below Android 10 reaches releases without current fixes (warning).
const ANDROID_10: u32 = 29;
/// MobSF: intent filter priorities above this are reported.
const HIGH_PRIORITY: i64 = 100;
const DIALER_CODE_SCHEME: &str = "android_secret_code";
const DATA_SMS_ACTION: &str = "android.intent.action.DATA_SMS_RECEIVED";

/// How a permission protecting a component is granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionLevel {
    /// `normal`: any app gets it.
    Normal,
    /// `dangerous`: any app the user approves gets it.
    Dangerous,
    /// `signature`: only apps signed with the same key.
    Signature,
    /// `signatureOrSystem`: same key or system apps.
    SignatureOrSystem,
    /// Defined neither by the app nor by the framework: another app defines it, or nobody does
    /// (then any app can define it first and grant it to itself).
    Unknown,
}

/// What protects an exported component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protection {
    /// Nothing: any app can call it.
    None,
    /// The component's own `android:permission`.
    Component(PermissionLevel),
    /// The application's `android:permission`, inherited.
    Application(PermissionLevel),
}

/// Why a component is reachable from other apps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportReason {
    /// `android:exported="true"`.
    Explicit,
    /// No `android:exported`, but an intent filter.
    IntentFilter,
    /// A provider in an app targeting API 16 or lower: exported by default.
    ProviderDefault,
    /// A provider in an app targeting API 17+ but installable on API 16 and lower, where
    /// providers are exported by default.
    ProviderDefaultOnOldDevices,
}

/// A manifest rule. [`ManifestRule::mobsf_key`] gives MobSF's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManifestRule {
    /// Minimum SDK below Android 8.0.
    VulnerableOsVersion,
    /// Minimum SDK below Android 10.
    VulnerableOsVersion2,
    /// `usesCleartextTraffic="true"`.
    ClearTextTraffic,
    /// `directBootAware="true"`.
    DirectBootAware,
    /// A network security configuration is declared.
    HasNetworkSecurity,
    /// `debuggable="true"`.
    AppIsDebuggable,
    /// `allowBackup="true"`.
    AppAllowBackup,
    /// `allowBackup` not set (Android allows backup by default).
    AllowBackupNotSet,
    /// `testOnly="true"`.
    AppInTestMode,
    /// An activity sets a `taskAffinity`.
    TaskAffinitySet,
    /// `singleTask`/`singleInstance` on an app installable below Android 5.0.
    NonStandardLaunchMode,
    /// StrandHogg 1.0: `singleTask` in an app targeting below Android 9.
    TaskHijacking,
    /// StrandHogg 2.0: exported activity in an app targeting below Android 10.
    TaskHijacking2,
    /// `<grant-uri-permission>` covering the whole provider.
    ImproperProviderPermission,
    /// Secret dialer code (`android_secret_code` scheme).
    DialerCodeFound,
    /// Data SMS receiver on a port.
    SmsReceiverPortFound,
    /// Intent filter priority above 100.
    HighIntentPriorityFound,
    /// A component reachable from other apps, with how it is protected.
    ExportedComponent(ExportReason, Protection),
    /// msec: cleartext allowed by Android's default (targets below Android 9, nothing set).
    CleartextByDefault,
    /// msec: user-installed CAs trusted by Android's default (targets below Android 7.0, no
    /// network security configuration).
    UserCertificatesTrustedByDefault,
    /// msec: http(s) links opened by the app without `autoVerify` (unverified App Links).
    UnverifiedAppLinks,
}

impl ManifestRule {
    /// Where the rule comes from.
    pub fn origin(self) -> Origin {
        match self {
            Self::CleartextByDefault
            | Self::UserCertificatesTrustedByDefault
            | Self::UnverifiedAppLinks => Origin::Msec,
            _ => Origin::MobSf,
        }
    }

    /// MobSF's severity (msec rules use the same scale).
    pub fn severity(self) -> Severity {
        match self {
            Self::VulnerableOsVersion
            | Self::ClearTextTraffic
            | Self::AppIsDebuggable
            | Self::AppInTestMode
            | Self::TaskHijacking
            | Self::TaskHijacking2 => Severity::High,
            Self::DirectBootAware | Self::HasNetworkSecurity => Severity::Info,
            Self::ExportedComponent(_, protection) => match protection {
                Protection::Component(level) | Protection::Application(level)
                    if matches!(
                        level,
                        PermissionLevel::Signature | PermissionLevel::SignatureOrSystem
                    ) =>
                {
                    Severity::Info
                }
                _ => Severity::Warning,
            },
            _ => Severity::Warning,
        }
    }

    /// MobSF's rule key (`kb/android_manifest_desc.py`); msec rules use `msec_` keys.
    pub fn mobsf_key(self) -> &'static str {
        match self {
            Self::VulnerableOsVersion => "vulnerable_os_version",
            Self::VulnerableOsVersion2 => "vulnerable_os_version2",
            Self::ClearTextTraffic => "clear_text_traffic",
            Self::DirectBootAware => "direct_boot_aware",
            Self::HasNetworkSecurity => "has_network_security",
            Self::AppIsDebuggable => "app_is_debuggable",
            Self::AppAllowBackup => "app_allowbackup",
            Self::AllowBackupNotSet => "allowbackup_not_set",
            Self::AppInTestMode => "app_in_test_mode",
            Self::TaskAffinitySet => "task_affinity_set",
            Self::NonStandardLaunchMode => "non_standard_launchmode",
            Self::TaskHijacking => "task_hijacking",
            Self::TaskHijacking2 => "task_hijacking2",
            Self::ImproperProviderPermission => "improper_provider_permission",
            Self::DialerCodeFound => "dialer_code_found",
            Self::SmsReceiverPortFound => "sms_receiver_port_found",
            Self::HighIntentPriorityFound => "high_intent_priority_found",
            Self::ExportedComponent(reason, protection) => export_key(reason, protection),
            Self::CleartextByDefault => "msec_cleartext_by_default",
            Self::UserCertificatesTrustedByDefault => "msec_user_certificates_trusted_by_default",
            Self::UnverifiedAppLinks => "msec_unverified_app_links",
        }
    }
}

/// MobSF's export decision table, in one place (upstream repeats it for each branch).
fn export_key(reason: ExportReason, protection: Protection) -> &'static str {
    use ExportReason::{Explicit, IntentFilter, ProviderDefault, ProviderDefaultOnOldDevices};
    use PermissionLevel::{Dangerous, Normal, Signature, SignatureOrSystem, Unknown};
    use Protection::{Application, Component};
    match (reason, protection) {
        (Explicit, Protection::None) => "explicitly_exported",
        (IntentFilter, Protection::None) => "exported_intent_filter_exists",
        (Explicit | IntentFilter, Component(Normal)) => "exported_protected_permission_normal",
        (Explicit | IntentFilter, Component(Dangerous)) => {
            "exported_protected_permission_dangerous"
        }
        (Explicit | IntentFilter, Component(Signature)) => {
            "exported_protected_permission_signature"
        }
        (Explicit | IntentFilter, Component(SignatureOrSystem)) => {
            "exported_protected_permission_signatureorsystem"
        }
        (Explicit | IntentFilter, Component(Unknown)) => {
            "exported_protected_permission_not_defined"
        }
        (Explicit | IntentFilter, Application(Normal)) => {
            "exported_protected_permission_normal_app_level"
        }
        (Explicit | IntentFilter, Application(Dangerous)) => {
            "exported_protected_permission_dangerous_app_level"
        }
        (Explicit | IntentFilter, Application(Signature)) => "exported_protected_permission",
        (Explicit | IntentFilter, Application(SignatureOrSystem)) => {
            "exported_protected_permission_signatureorsystem_app_level"
        }
        (Explicit | IntentFilter, Application(Unknown)) => {
            "exported_protected_permission_app_level"
        }
        (ProviderDefault, Protection::None) => "exported_provider",
        (ProviderDefault, Component(Normal)) => "exported_provider_normal",
        (ProviderDefault, Component(Dangerous)) => "exported_provider_danger",
        (ProviderDefault, Component(Signature)) => "exported_provider_signature",
        (ProviderDefault, Component(SignatureOrSystem)) => "exported_provider_signatureorsystem",
        (ProviderDefault, Component(Unknown)) => "exported_provider_unknown",
        (ProviderDefault, Application(Normal)) => "exported_provider_normal_app",
        (ProviderDefault, Application(Dangerous)) => "exported_provider_danger_appl",
        (ProviderDefault, Application(Signature)) => "exported_provider_signature_appl",
        (ProviderDefault, Application(SignatureOrSystem)) => {
            "exported_provider_signatureorsystem_app"
        }
        (ProviderDefault, Application(Unknown)) => "exported_provider_unknown_app",
        (ProviderDefaultOnOldDevices, Protection::None) => "exported_provider_2",
        (ProviderDefaultOnOldDevices, Component(Normal)) => "exported_provider_normal_new",
        (ProviderDefaultOnOldDevices, Component(Dangerous)) => "exported_provider_danger_new",
        (ProviderDefaultOnOldDevices, Component(Signature)) => "exported_provider_signature_new",
        (ProviderDefaultOnOldDevices, Component(SignatureOrSystem)) => {
            "exported_provider_signatureorsystem_new"
        }
        (ProviderDefaultOnOldDevices, Component(Unknown)) => "exported_provider_unknown_new",
        (ProviderDefaultOnOldDevices, Application(Normal)) => "exported_provider_normal_app_new",
        (ProviderDefaultOnOldDevices, Application(Dangerous)) => "exported_provider_danger_app_new",
        (ProviderDefaultOnOldDevices, Application(Signature)) => {
            "exported_provider_signature_app_new"
        }
        (ProviderDefaultOnOldDevices, Application(SignatureOrSystem)) => {
            "exported_provider_signatureorsystem_app_new"
        }
        (ProviderDefaultOnOldDevices, Application(Unknown)) => "exported_provider_unknown_app_new",
    }
}

/// One manifest finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFinding {
    /// The rule.
    pub rule: ManifestRule,
    /// The component, for component rules.
    pub component: Option<(ComponentKind, String)>,
    /// The permission protecting an exported component.
    pub permission: Option<String>,
    /// The value that triggered the rule: SDK level, priority, dialer code, port, path, link.
    pub detail: Option<String>,
}

impl ManifestFinding {
    fn app(rule: ManifestRule, detail: Option<String>) -> Self {
        Self {
            rule,
            component: None,
            permission: None,
            detail,
        }
    }

    fn component(rule: ManifestRule, component: &Component, detail: Option<String>) -> Self {
        Self {
            rule,
            component: Some((component.kind, component.name.clone())),
            permission: None,
            detail,
        }
    }

    /// The rule's severity.
    pub fn severity(&self) -> Severity {
        self.rule.severity()
    }
}

/// Runs every manifest check. `network_security_config` is the resolved name of the configured
/// file (for example `@xml/network_security_config`), when there is one.
pub fn analyse_manifest(
    manifest: &Manifest,
    network_security_config: Option<&str>,
) -> Vec<ManifestFinding> {
    let mut findings = platform_findings(manifest);
    let Some(application) = &manifest.application else {
        return findings;
    };
    findings.extend(application_findings(
        manifest,
        application,
        network_security_config,
    ));
    let main_activity = application
        .components
        .iter()
        .find(|component| component.is_launcher());
    for component in &application.components {
        if matches!(
            component.kind,
            ComponentKind::Activity | ComponentKind::ActivityAlias
        ) {
            findings.extend(activity_findings(manifest, component));
        }
        let is_main = main_activity.is_some_and(|main| std::ptr::eq(main, component));
        if !is_main && let Some(finding) = export_finding(manifest, application, component) {
            findings.push(finding);
        }
    }
    findings.extend(provider_grant_findings(application));
    findings.extend(intent_data_findings(application));
    findings.extend(intent_priority_findings(application));
    findings.extend(unverified_app_link_findings(manifest, application));
    findings
}

fn platform_findings(manifest: &Manifest) -> Vec<ManifestFinding> {
    let Some(min_sdk) = manifest.min_sdk() else {
        return Vec::new();
    };
    let rule = if min_sdk < ANDROID_8_0 {
        ManifestRule::VulnerableOsVersion
    } else if min_sdk < ANDROID_10 {
        ManifestRule::VulnerableOsVersion2
    } else {
        return Vec::new();
    };
    vec![ManifestFinding::app(rule, Some(min_sdk.to_string()))]
}

fn application_findings(
    manifest: &Manifest,
    application: &Application,
    network_security_config: Option<&str>,
) -> Vec<ManifestFinding> {
    let mut findings = Vec::new();
    let mut flag = |condition: bool, rule: ManifestRule, detail: Option<String>| {
        if condition {
            findings.push(ManifestFinding::app(rule, detail));
        }
    };
    flag(
        application.uses_cleartext_traffic == Some(true),
        ManifestRule::ClearTextTraffic,
        None,
    );
    flag(
        application.direct_boot_aware == Some(true),
        ManifestRule::DirectBootAware,
        None,
    );
    flag(
        application.network_security_config.is_some(),
        ManifestRule::HasNetworkSecurity,
        network_security_config.map(str::to_owned),
    );
    flag(
        application.debuggable == Some(true),
        ManifestRule::AppIsDebuggable,
        None,
    );
    flag(
        application.allow_backup == Some(true),
        ManifestRule::AppAllowBackup,
        None,
    );
    flag(
        application.allow_backup.is_none(),
        ManifestRule::AllowBackupNotSet,
        None,
    );
    flag(
        application.test_only == Some(true),
        ManifestRule::AppInTestMode,
        None,
    );

    let target_sdk = manifest.target_sdk().unwrap_or(1);
    let has_config = application.network_security_config.is_some();
    flag(
        application.uses_cleartext_traffic.is_none() && !has_config && target_sdk < ANDROID_9,
        ManifestRule::CleartextByDefault,
        Some(target_sdk.to_string()),
    );
    flag(
        !has_config && target_sdk < ANDROID_7_0,
        ManifestRule::UserCertificatesTrustedByDefault,
        Some(target_sdk.to_string()),
    );
    findings
}

fn activity_findings(manifest: &Manifest, activity: &Component) -> Vec<ManifestFinding> {
    let mut findings = Vec::new();
    let affinity_set = activity
        .task_affinity
        .as_deref()
        .is_some_and(|affinity| !affinity.is_empty());
    if affinity_set {
        findings.push(ManifestFinding::component(
            ManifestRule::TaskAffinitySet,
            activity,
            activity.task_affinity.clone(),
        ));
    }
    let min_sdk = manifest.min_sdk().unwrap_or(1);
    let reuses_task = matches!(
        activity.launch_mode,
        Some(LaunchMode::SingleTask | LaunchMode::SingleInstance)
    );
    if min_sdk < ANDROID_5_0 && reuses_task {
        findings.push(ManifestFinding::component(
            ManifestRule::NonStandardLaunchMode,
            activity,
            None,
        ));
    }
    let target_sdk = manifest.target_sdk().unwrap_or(1);
    if target_sdk < ANDROID_9 && activity.launch_mode == Some(LaunchMode::SingleTask) {
        findings.push(ManifestFinding::component(
            ManifestRule::TaskHijacking,
            activity,
            Some(target_sdk.to_string()),
        ));
    }
    let single_instance = activity.launch_mode == Some(LaunchMode::SingleInstance);
    if target_sdk < ANDROID_10
        && activity.exported == Some(true)
        && (!single_instance || affinity_set)
    {
        findings.push(ManifestFinding::component(
            ManifestRule::TaskHijacking2,
            activity,
            Some(target_sdk.to_string()),
        ));
    }
    findings
}

/// The export decision for one component, or `None` when it is not reachable.
fn export_finding(
    manifest: &Manifest,
    application: &Application,
    component: &Component,
) -> Option<ManifestFinding> {
    let reason = export_reason(manifest, component)?;
    let (protection, permission) = match (&component.permission, &application.permission) {
        (Some(permission), _) => (
            Protection::Component(permission_level(manifest, permission)),
            Some(permission),
        ),
        (None, Some(permission)) => (
            Protection::Application(permission_level(manifest, permission)),
            Some(permission),
        ),
        (None, None) => (Protection::None, None),
    };
    Some(ManifestFinding {
        rule: ManifestRule::ExportedComponent(reason, protection),
        component: Some((component.kind, component.name.clone())),
        permission: permission.cloned(),
        detail: None,
    })
}

fn export_reason(manifest: &Manifest, component: &Component) -> Option<ExportReason> {
    match component.exported {
        Some(true) => Some(ExportReason::Explicit),
        Some(false) => None,
        None if !component.intent_filters.is_empty() => Some(ExportReason::IntentFilter),
        None if component.kind == ComponentKind::Provider => {
            let min_sdk = manifest.min_sdk().unwrap_or(1);
            let target_sdk = manifest.target_sdk().unwrap_or(1);
            if min_sdk >= ANDROID_4_2 {
                None
            } else if target_sdk < ANDROID_4_2 {
                Some(ExportReason::ProviderDefault)
            } else {
                Some(ExportReason::ProviderDefaultOnOldDevices)
            }
        }
        None => None,
    }
}

/// The level of a permission defined by the app, else by the framework (MobSF only knows the
/// app's own permissions).
fn permission_level(manifest: &Manifest, name: &str) -> PermissionLevel {
    if let Some(declared) = manifest
        .permissions
        .iter()
        .find(|permission| permission.name == name)
    {
        return match declared.protection_level & 0xf {
            0 => PermissionLevel::Normal,
            1 => PermissionLevel::Dangerous,
            2 => PermissionLevel::Signature,
            3 => PermissionLevel::SignatureOrSystem,
            _ => PermissionLevel::Unknown,
        };
    }
    let Some(framework) = framework_permission(name) else {
        return PermissionLevel::Unknown;
    };
    match framework
        .protection_level
        .split('|')
        .next()
        .unwrap_or("normal")
    {
        "normal" => PermissionLevel::Normal,
        "dangerous" => PermissionLevel::Dangerous,
        "signatureOrSystem" => PermissionLevel::SignatureOrSystem,
        // signature, internal, role, module, system: not grantable to ordinary apps.
        _ => PermissionLevel::Signature,
    }
}

fn provider_grant_findings(application: &Application) -> Vec<ManifestFinding> {
    let mut findings = Vec::new();
    for provider in application.components_of(ComponentKind::Provider) {
        for grant in &provider.grant_uri_permission_paths {
            let whole_provider = if grant.path_prefix.as_deref() == Some("/") {
                Some("pathPrefix=/")
            } else if grant.path.as_deref() == Some("/") {
                Some("path=/")
            } else if grant.path_pattern.as_deref() == Some("*") {
                Some("pathPattern=*")
            } else {
                None
            };
            if let Some(detail) = whole_provider {
                findings.push(ManifestFinding::component(
                    ManifestRule::ImproperProviderPermission,
                    provider,
                    Some(detail.to_owned()),
                ));
            }
        }
    }
    findings
}

fn filters(application: &Application) -> impl Iterator<Item = (&Component, &IntentFilter)> {
    application.components.iter().flat_map(|component| {
        component
            .intent_filters
            .iter()
            .map(move |filter| (component, filter))
    })
}

/// Secret dialer codes, and data SMS receivers. MobSF reports every `android:port`; msec only
/// ports on data SMS receivers (a port on a web link is not an SMS port).
fn intent_data_findings(application: &Application) -> Vec<ManifestFinding> {
    let mut findings = Vec::new();
    for (component, filter) in filters(application) {
        let data_sms = filter.has_action(DATA_SMS_ACTION);
        for data in &filter.data {
            if data.scheme.as_deref() == Some(DIALER_CODE_SCHEME) {
                findings.push(ManifestFinding::component(
                    ManifestRule::DialerCodeFound,
                    component,
                    data.host.clone(),
                ));
            } else if let Some(port) = &data.port
                && (data_sms || data.scheme.as_deref() == Some("sms"))
            {
                findings.push(ManifestFinding::component(
                    ManifestRule::SmsReceiverPortFound,
                    component,
                    Some(port.clone()),
                ));
            }
        }
    }
    findings
}

/// One finding per distinct high priority, with the number of filters using it.
fn intent_priority_findings(application: &Application) -> Vec<ManifestFinding> {
    let mut counts: Vec<(i64, usize)> = Vec::new();
    for (_, filter) in filters(application) {
        let Some(priority) = filter.priority.filter(|&priority| priority > HIGH_PRIORITY) else {
            continue;
        };
        match counts.iter_mut().find(|(value, _)| *value == priority) {
            Some((_, count)) => *count += 1,
            None => counts.push((priority, 1)),
        }
    }
    counts
        .into_iter()
        .map(|(priority, count)| {
            ManifestFinding::app(
                ManifestRule::HighIntentPriorityFound,
                Some(format!("{priority} ({count} hits)")),
            )
        })
        .collect()
}

/// Browsable http(s) filters with hosts but without `autoVerify`: any app can claim the same
/// links, and Android asks the user which app opens them.
fn unverified_app_link_findings(
    manifest: &Manifest,
    application: &Application,
) -> Vec<ManifestFinding> {
    let target_sdk = manifest.target_sdk().unwrap_or(1);
    let mut findings = Vec::new();
    for (component, filter) in filters(application) {
        let reachable = component.is_exported(target_sdk)
            && matches!(
                component.kind,
                ComponentKind::Activity | ComponentKind::ActivityAlias
            );
        if !reachable || !filter.is_browsable() || filter.auto_verify == Some(true) {
            continue;
        }
        let web = filter
            .schemes()
            .into_iter()
            .any(|scheme| scheme == "http" || scheme == "https");
        for host in filter.hosts().into_iter().filter(|_| web) {
            findings.push(ManifestFinding::component(
                ManifestRule::UnverifiedAppLinks,
                component,
                Some(host.to_owned()),
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_keys_match_mobsf_templates() {
        // Every key exists in MobSF's MANIFEST_DESC (spot checks across the table).
        let key =
            |reason, protection| ManifestRule::ExportedComponent(reason, protection).mobsf_key();
        assert_eq!(
            key(ExportReason::Explicit, Protection::None),
            "explicitly_exported"
        );
        assert_eq!(
            key(
                ExportReason::IntentFilter,
                Protection::Application(PermissionLevel::Signature)
            ),
            "exported_protected_permission"
        );
        assert_eq!(
            key(
                ExportReason::ProviderDefault,
                Protection::Application(PermissionLevel::Dangerous)
            ),
            "exported_provider_danger_appl"
        );
        assert_eq!(
            key(
                ExportReason::ProviderDefaultOnOldDevices,
                Protection::Component(PermissionLevel::Unknown)
            ),
            "exported_provider_unknown_new"
        );
    }

    #[test]
    fn signature_protection_is_info_everything_else_a_warning() {
        let severity = |protection| {
            ManifestRule::ExportedComponent(ExportReason::Explicit, protection).severity()
        };
        assert_eq!(
            severity(Protection::Component(PermissionLevel::Signature)),
            Severity::Info
        );
        assert_eq!(
            severity(Protection::Application(PermissionLevel::SignatureOrSystem)),
            Severity::Info
        );
        assert_eq!(
            severity(Protection::Component(PermissionLevel::Normal)),
            Severity::Warning
        );
        assert_eq!(severity(Protection::None), Severity::Warning);
    }
}
