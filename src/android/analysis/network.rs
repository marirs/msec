//! Network security configuration (`res/xml/...`, referenced by
//! `android:networkSecurityConfig`): a typed model and MobSF's `network_security.py` checks.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{Origin, Severity};
use crate::android::resources::ResourceTable;
use crate::android::value::Value;
use crate::android::xml::{XmlDocument, XmlElement, XmlNode};

/// Where trusted certificates come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSource {
    /// The system CA store.
    System,
    /// User-installed CAs.
    User,
    /// Certificates bundled with the app (`@raw/...`).
    Bundled(String),
    /// Anything else, as written.
    Other(String),
}

/// One `<certificates>` entry of `<trust-anchors>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The source.
    pub source: CertificateSource,
    /// `overridePins="true"`: these CAs bypass certificate pinning.
    pub override_pins: bool,
}

/// Settings shared by base, domain and debug configurations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// `cleartextTrafficPermitted`, when set.
    pub cleartext_permitted: Option<bool>,
    /// Trust anchors.
    pub trust_anchors: Vec<TrustAnchor>,
}

/// A `<pin>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Digest algorithm (`SHA-256`).
    pub digest: Option<String>,
    /// Base64 digest of the public key.
    pub value: String,
}

/// A `<pin-set>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinSet {
    /// `expiration` (`yyyy-MM-dd`): after it, pinning is not enforced.
    pub expiration: Option<String>,
    /// Pins.
    pub pins: Vec<Pin>,
}

/// A `<domain>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    /// Host name.
    pub name: String,
    /// `includeSubdomains`.
    pub include_subdomains: bool,
}

/// A `<domain-config>` (nested ones are flattened; cleartext inherits from the parent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainConfig {
    /// Domains in scope.
    pub domains: Vec<Domain>,
    /// Cleartext and trust settings.
    pub policy: Policy,
    /// Pins, when set.
    pub pin_set: Option<PinSet>,
}

/// A decoded network security configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSecurityConfig {
    /// `<base-config>`.
    pub base: Option<Policy>,
    /// `<domain-config>`s.
    pub domains: Vec<DomainConfig>,
    /// `<debug-overrides>` (only applied when the app is debuggable).
    pub debug_overrides: Option<Policy>,
}

impl NetworkSecurityConfig {
    /// Reads the configuration from its decoded document. `resources` names `@raw/` references.
    pub fn from_document(document: &XmlDocument, resources: Option<&ResourceTable>) -> Self {
        let mut config = Self::default();
        let Some(root) = &document.root else {
            return config;
        };
        for child in root.elements() {
            match child.name.as_str() {
                "base-config" => config.base = Some(read_policy(child, resources, None)),
                "domain-config" => read_domain_config(child, resources, None, &mut config.domains),
                "debug-overrides" => {
                    config.debug_overrides = Some(read_policy(child, resources, None))
                }
                _ => {}
            }
        }
        config
    }
}

fn plain(element: &XmlElement, name: &str) -> Option<Value> {
    element.plain_attribute(name).cloned()
}

fn read_policy(
    element: &XmlElement,
    resources: Option<&ResourceTable>,
    inherited_cleartext: Option<bool>,
) -> Policy {
    Policy {
        cleartext_permitted: plain(element, "cleartextTrafficPermitted")
            .and_then(|value| value.as_bool())
            .or(inherited_cleartext),
        trust_anchors: element
            .elements_named("trust-anchors")
            .flat_map(|anchors| anchors.elements_named("certificates"))
            .map(|certificates| TrustAnchor {
                source: certificate_source(plain(certificates, "src"), resources),
                override_pins: plain(certificates, "overridePins")
                    .and_then(|value| value.as_bool())
                    == Some(true),
            })
            .collect(),
    }
}

fn certificate_source(
    value: Option<Value>,
    resources: Option<&ResourceTable>,
) -> CertificateSource {
    match value {
        Some(Value::String(Some(text))) => match text.as_str() {
            "system" => CertificateSource::System,
            "user" => CertificateSource::User,
            other if other.starts_with("@raw/") => CertificateSource::Bundled(other.to_owned()),
            other => CertificateSource::Other(other.to_owned()),
        },
        Some(Value::Reference(id)) => {
            let name = resources.and_then(|table| table.name(id));
            match name {
                Some(name) if name.type_name == "raw" => {
                    CertificateSource::Bundled(format!("@raw/{}", name.entry))
                }
                Some(name) => {
                    CertificateSource::Other(format!("@{}/{}", name.type_name, name.entry))
                }
                None => CertificateSource::Bundled(format!("@0x{id:08x}")),
            }
        }
        Some(other) => CertificateSource::Other(other.to_string()),
        None => CertificateSource::Other(String::new()),
    }
}

fn read_domain_config(
    element: &XmlElement,
    resources: Option<&ResourceTable>,
    parent_cleartext: Option<bool>,
    out: &mut Vec<DomainConfig>,
) {
    let policy = read_policy(element, resources, parent_cleartext);
    let domains = element
        .elements_named("domain")
        .map(|domain| Domain {
            name: text_content(domain),
            include_subdomains: plain(domain, "includeSubdomains")
                .and_then(|value| value.as_bool())
                == Some(true),
        })
        .collect();
    let pin_set = element.elements_named("pin-set").next().map(|pins| PinSet {
        expiration: plain(pins, "expiration").map(|value| value.to_string()),
        pins: pins
            .elements_named("pin")
            .map(|pin| Pin {
                digest: plain(pin, "digest").map(|value| value.to_string()),
                value: text_content(pin),
            })
            .collect(),
    });
    let cleartext = policy.cleartext_permitted;
    out.push(DomainConfig {
        domains,
        policy,
        pin_set,
    });
    for nested in element.elements_named("domain-config") {
        read_domain_config(nested, resources, cleartext, out);
    }
}

fn text_content(element: &XmlElement) -> String {
    element
        .children
        .iter()
        .filter_map(|child| match child {
            XmlNode::Text(text) => Some(text.trim()),
            XmlNode::Element(_) => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

/// A network security rule (MobSF has no keys for these; msec names them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkRule {
    /// Cleartext permitted.
    CleartextPermitted,
    /// Cleartext explicitly refused.
    CleartextBlocked,
    /// Trusts bundled certificates.
    TrustsBundledCertificates,
    /// Trusts the system CA store.
    TrustsSystemCertificates,
    /// Trusts user-installed CAs.
    TrustsUserCertificates,
    /// Trust anchors bypass pinning.
    OverridesPins,
    /// Pinning with an expiry date.
    PinsExpire,
    /// Pinning without an expiry date.
    PinsDoNotExpire,
    /// msec: the pin-set expiry date has passed, so pinning is no longer enforced.
    PinsExpired,
}

/// Which part of the configuration a finding is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// `<base-config>`: all domains.
    Base,
    /// A `<domain-config>`: these domains.
    Domains(Vec<String>),
    /// `<debug-overrides>` in a debuggable app.
    DebugOverrides,
}

/// One network security finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkFinding {
    /// The rule.
    pub rule: NetworkRule,
    /// Where it applies.
    pub scope: Scope,
    /// Extra context: certificate source, expiry date, pins.
    pub detail: Option<String>,
}

impl NetworkFinding {
    /// MobSF's severity for this finding (debug overrides raise bundled certificates to high).
    pub fn severity(&self) -> Severity {
        match (self.rule, &self.scope) {
            (NetworkRule::TrustsBundledCertificates, Scope::DebugOverrides) => Severity::High,
            (
                NetworkRule::CleartextPermitted
                | NetworkRule::TrustsUserCertificates
                | NetworkRule::OverridesPins,
                _,
            ) => Severity::High,
            (NetworkRule::TrustsSystemCertificates | NetworkRule::PinsExpired, _) => {
                Severity::Warning
            }
            (NetworkRule::TrustsBundledCertificates | NetworkRule::PinsExpire, _) => Severity::Info,
            (NetworkRule::CleartextBlocked | NetworkRule::PinsDoNotExpire, _) => Severity::Secure,
        }
    }

    /// Where the rule comes from.
    pub fn origin(&self) -> Origin {
        if self.rule == NetworkRule::PinsExpired {
            Origin::Msec
        } else {
            Origin::MobSf
        }
    }
}

/// MobSF's checks, plus expired pins. `today` is `yyyy-MM-dd`; see [`today_utc`].
pub fn analyse_network_security(
    config: &NetworkSecurityConfig,
    debuggable: bool,
    today: &str,
) -> Vec<NetworkFinding> {
    let mut findings = Vec::new();
    if let Some(base) = &config.base {
        policy_findings(base, &Scope::Base, &mut findings);
    }
    for domain in &config.domains {
        let scope = Scope::Domains(
            domain
                .domains
                .iter()
                .map(|domain| domain.name.clone())
                .collect(),
        );
        policy_findings(&domain.policy, &scope, &mut findings);
        if let Some(pins) = &domain.pin_set {
            pin_findings(pins, &scope, today, &mut findings);
        }
    }
    if let (Some(debug), true) = (&config.debug_overrides, debuggable) {
        debug_findings(debug, &mut findings);
    }
    findings
}

fn policy_findings(policy: &Policy, scope: &Scope, findings: &mut Vec<NetworkFinding>) {
    let mut push = |rule, detail: Option<String>| {
        findings.push(NetworkFinding {
            rule,
            scope: scope.clone(),
            detail,
        })
    };
    match policy.cleartext_permitted {
        Some(true) => push(NetworkRule::CleartextPermitted, None),
        Some(false) => push(NetworkRule::CleartextBlocked, None),
        None => {}
    }
    for anchor in &policy.trust_anchors {
        match &anchor.source {
            CertificateSource::Bundled(name) => {
                push(NetworkRule::TrustsBundledCertificates, Some(name.clone()))
            }
            CertificateSource::System => push(NetworkRule::TrustsSystemCertificates, None),
            CertificateSource::User => push(NetworkRule::TrustsUserCertificates, None),
            CertificateSource::Other(_) => {}
        }
        if anchor.override_pins {
            push(NetworkRule::OverridesPins, None);
        }
    }
}

fn pin_findings(pins: &PinSet, scope: &Scope, today: &str, findings: &mut Vec<NetworkFinding>) {
    let rule = match &pins.expiration {
        // ISO dates compare correctly as strings.
        Some(expiration) if expiration.as_str() < today => NetworkRule::PinsExpired,
        Some(_) => NetworkRule::PinsExpire,
        None => NetworkRule::PinsDoNotExpire,
    };
    findings.push(NetworkFinding {
        rule,
        scope: scope.clone(),
        detail: pins.expiration.clone(),
    });
}

/// Debug overrides apply only to debuggable builds; MobSF checks cleartext, bundled
/// certificates and pin overrides there.
fn debug_findings(debug: &Policy, findings: &mut Vec<NetworkFinding>) {
    let scope = Scope::DebugOverrides;
    if debug.cleartext_permitted == Some(true) {
        findings.push(NetworkFinding {
            rule: NetworkRule::CleartextPermitted,
            scope: scope.clone(),
            detail: None,
        });
    }
    for anchor in &debug.trust_anchors {
        if let CertificateSource::Bundled(name) = &anchor.source {
            findings.push(NetworkFinding {
                rule: NetworkRule::TrustsBundledCertificates,
                scope: scope.clone(),
                detail: Some(name.clone()),
            });
        }
        if anchor.override_pins {
            findings.push(NetworkFinding {
                rule: NetworkRule::OverridesPins,
                scope: scope.clone(),
                detail: None,
            });
        }
    }
}

/// Today's date in UTC as `yyyy-MM-dd`, for [`analyse_network_security`].
pub fn today_utc() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() / 86_400);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_are_correct() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_739), (2026, 10, 13));
        assert_eq!(today_utc().len(), 10);
    }

    #[test]
    fn expired_pins_are_reported_as_such() {
        let pins = PinSet {
            expiration: Some("2024-01-01".into()),
            pins: Vec::new(),
        };
        let mut findings = Vec::new();
        pin_findings(&pins, &Scope::Base, "2026-10-13", &mut findings);
        assert_eq!(findings[0].rule, NetworkRule::PinsExpired);
        findings.clear();
        pin_findings(&pins, &Scope::Base, "2023-06-01", &mut findings);
        assert_eq!(findings[0].rule, NetworkRule::PinsExpire);
    }
}
