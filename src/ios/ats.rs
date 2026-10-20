//! App Transport Security: what `NSAppTransportSecurity` in `Info.plist` relaxes, read with the
//! semantics Apple documents (`Information Property List > NSAppTransportSecurity`):
//!
//! - on iOS 10 and later, `NSAllowsArbitraryLoads` is ignored when any of
//!   `NSAllowsArbitraryLoadsForMedia`, `NSAllowsArbitraryLoadsInWebContent` or
//!   `NSAllowsLocalNetworking` is present; [`TransportSecurity::arbitrary_loads_effective`]
//!   applies that to the app's minimum iOS version;
//! - exception domains relax ATS for one host (and its subdomains with `NSIncludesSubdomains`),
//!   with the current keys or their `NSThirdParty...` and `NSTemporary...` variants;
//! - the default minimum is TLS 1.2, with forward secrecy required.
//!
//! MobSF (`app_transport_security.py`) reports every key whatever the others say, and grades
//! an exception's TLS 1.2 minimum as a warning; msec reports what is in effect, and a TLS 1.2
//! minimum as the default it is. See `docs/PORTING.md`.

use crate::plist::{Dictionary, Value};

/// Hosts exempt from the insecure-HTTP finding (MobSF exempts the same two).
const LOOPBACK_HOSTS: [&str; 2] = ["localhost", "127.0.0.1"];

/// The `NSAppTransportSecurity` dictionary, read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportSecurity {
    /// `NSAppTransportSecurity` is present.
    pub declared: bool,
    /// `NSAllowsArbitraryLoads`.
    pub allows_arbitrary_loads: Option<bool>,
    /// `NSAllowsArbitraryLoadsForMedia`.
    pub allows_arbitrary_loads_for_media: Option<bool>,
    /// `NSAllowsArbitraryLoadsInWebContent`.
    pub allows_arbitrary_loads_in_web_content: Option<bool>,
    /// `NSAllowsLocalNetworking`.
    pub allows_local_networking: Option<bool>,
    /// `NSExceptionDomains`, in the order the plist names them.
    pub exception_domains: Vec<ExceptionDomain>,
    /// `NSPinnedDomains` (iOS 14+): domains whose certificates are pinned.
    pub pinned_domains: Vec<String>,
    /// Keys with a type other than ATS reads (`NSAllowsArbitraryLoads` as a string).
    pub wrong_types: Vec<String>,
}

/// One exception domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionDomain {
    /// The domain as written.
    pub domain: String,
    /// `NSIncludesSubdomains`.
    pub includes_subdomains: bool,
    /// Plain HTTP allowed (`NSExceptionAllowsInsecureHTTPLoads` or a variant), with the key
    /// that allows it.
    pub insecure_http: Option<String>,
    /// The minimum TLS version (`NSExceptionMinimumTLSVersion` or a variant).
    pub minimum_tls: Option<String>,
    /// Forward secrecy required (`NSExceptionRequiresForwardSecrecy` or a variant; ATS
    /// requires it unless set to false).
    pub requires_forward_secrecy: Option<bool>,
    /// `NSRequiresCertificateTransparency`.
    pub requires_certificate_transparency: Option<bool>,
}

impl ExceptionDomain {
    /// The host is a loopback name (local development).
    pub fn is_loopback(&self) -> bool {
        LOOPBACK_HOSTS.contains(&self.domain.as_str())
    }

    /// The minimum TLS version is below 1.2 (TLS 1.0 or 1.1).
    pub fn weak_tls(&self) -> bool {
        matches!(self.minimum_tls.as_deref(), Some("TLSv1.0" | "TLSv1.1"))
    }
}

impl TransportSecurity {
    /// Reads `NSAppTransportSecurity` from an `Info.plist` dictionary.
    pub fn of(info: &Dictionary) -> Self {
        let Some(value) = info.get("NSAppTransportSecurity") else {
            return Self::default();
        };
        let mut ats = Self {
            declared: true,
            ..Self::default()
        };
        let Some(dictionary) = value.as_dictionary() else {
            ats.wrong_types.push("NSAppTransportSecurity".to_owned());
            return ats;
        };
        let flag = |key: &str, wrong: &mut Vec<String>| match dictionary.get(key) {
            None => None,
            Some(Value::Boolean(value)) => Some(*value),
            Some(_) => {
                wrong.push(key.to_owned());
                None
            }
        };
        let mut wrong = Vec::new();
        ats.allows_arbitrary_loads = flag("NSAllowsArbitraryLoads", &mut wrong);
        ats.allows_arbitrary_loads_for_media = flag("NSAllowsArbitraryLoadsForMedia", &mut wrong);
        ats.allows_arbitrary_loads_in_web_content =
            flag("NSAllowsArbitraryLoadsInWebContent", &mut wrong);
        ats.allows_local_networking = flag("NSAllowsLocalNetworking", &mut wrong);
        if let Some(domains) = dictionary.get("NSExceptionDomains") {
            match domains.as_dictionary() {
                Some(domains) => {
                    for (domain, settings) in domains.iter() {
                        match settings.as_dictionary() {
                            Some(settings) => ats
                                .exception_domains
                                .push(exception_domain(domain, settings, &mut wrong)),
                            None => wrong.push(format!("NSExceptionDomains/{domain}")),
                        }
                    }
                }
                None => wrong.push("NSExceptionDomains".to_owned()),
            }
        }
        if let Some(pinned) = dictionary.get("NSPinnedDomains") {
            match pinned.as_dictionary() {
                Some(pinned) => {
                    ats.pinned_domains =
                        pinned.iter().map(|(domain, _)| domain.to_owned()).collect();
                }
                None => wrong.push("NSPinnedDomains".to_owned()),
            }
        }
        ats.wrong_types = wrong;
        ats
    }

    /// Whether `NSAllowsArbitraryLoads` is in effect for an app whose minimum iOS version is
    /// `minimum_os` (`17.0`): iOS 10 and later ignore it when a narrower key is present. An
    /// unreadable minimum version is taken as 10 or later (every current toolchain's floor).
    pub fn arbitrary_loads_effective(&self, minimum_os: Option<&str>) -> bool {
        if self.allows_arbitrary_loads != Some(true) {
            return false;
        }
        let narrower = self.allows_arbitrary_loads_for_media.is_some()
            || self.allows_arbitrary_loads_in_web_content.is_some()
            || self.allows_local_networking.is_some();
        let before_ios_10 = minimum_os
            .and_then(|version| version.split('.').next()?.parse::<u32>().ok())
            .is_some_and(|major| major < 10);
        !narrower || before_ios_10
    }

    /// The narrower key that makes iOS 10+ ignore `NSAllowsArbitraryLoads`, if any.
    pub fn arbitrary_loads_overridden_by(&self) -> Option<&'static str> {
        if self.allows_arbitrary_loads_for_media.is_some() {
            Some("NSAllowsArbitraryLoadsForMedia")
        } else if self.allows_arbitrary_loads_in_web_content.is_some() {
            Some("NSAllowsArbitraryLoadsInWebContent")
        } else if self.allows_local_networking.is_some() {
            Some("NSAllowsLocalNetworking")
        } else {
            None
        }
    }
}

/// One exception domain's settings, current keys first, then the third-party and temporary
/// variants older configurations use.
fn exception_domain(
    domain: &str,
    settings: &Dictionary,
    wrong: &mut Vec<String>,
) -> ExceptionDomain {
    let mut flag = |key: &str| match settings.get(key) {
        None => None,
        Some(Value::Boolean(value)) => Some(*value),
        Some(_) => {
            wrong.push(format!("NSExceptionDomains/{domain}/{key}"));
            None
        }
    };
    let insecure_keys = [
        "NSExceptionAllowsInsecureHTTPLoads",
        "NSThirdPartyExceptionAllowsInsecureHTTPLoads",
        "NSTemporaryExceptionAllowsInsecureHTTPLoads",
        "NSTemporaryThirdPartyExceptionAllowsInsecureHTTPLoads",
    ];
    let insecure_http = insecure_keys
        .iter()
        .find(|key| flag(key) == Some(true))
        .map(|key| (*key).to_owned());
    let includes_subdomains = flag("NSIncludesSubdomains") == Some(true);
    let requires_forward_secrecy = [
        "NSExceptionRequiresForwardSecrecy",
        "NSThirdPartyExceptionRequiresForwardSecrecy",
        "NSTemporaryExceptionRequiresForwardSecrecy",
        "NSTemporaryThirdPartyExceptionRequiresForwardSecrecy",
    ]
    .iter()
    .find_map(|key| flag(key));
    let requires_certificate_transparency = flag("NSRequiresCertificateTransparency");
    let minimum_tls = [
        "NSExceptionMinimumTLSVersion",
        "NSThirdPartyExceptionMinimumTLSVersion",
        "NSTemporaryExceptionMinimumTLSVersion",
        "NSTemporaryThirdPartyExceptionMinimumTLSVersion",
    ]
    .iter()
    .find_map(|key| settings.get(key).and_then(Value::as_str).map(str::to_owned));
    ExceptionDomain {
        domain: domain.to_owned(),
        includes_subdomains,
        insecure_http,
        minimum_tls,
        requires_forward_secrecy,
        requires_certificate_transparency,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plist;

    fn ats(xml: &str) -> TransportSecurity {
        let document = format!(
            "<plist><dict><key>NSAppTransportSecurity</key><dict>{xml}</dict></dict></plist>"
        );
        let parsed = plist::parse(document.as_bytes()).unwrap();
        TransportSecurity::of(parsed.root.as_dictionary().unwrap())
    }

    #[test]
    fn arbitrary_loads_follow_apples_override_rule() {
        let alone = ats("<key>NSAllowsArbitraryLoads</key><true/>");
        assert!(alone.arbitrary_loads_effective(Some("17.0")));
        let overridden = ats("<key>NSAllowsArbitraryLoads</key><true/>\
             <key>NSAllowsArbitraryLoadsInWebContent</key><true/>");
        assert!(!overridden.arbitrary_loads_effective(Some("17.0")));
        assert!(overridden.arbitrary_loads_effective(Some("9.3")));
        assert_eq!(
            overridden.arbitrary_loads_overridden_by(),
            Some("NSAllowsArbitraryLoadsInWebContent")
        );
        // Even a false narrower key overrides it: Apple names presence, not value.
        let false_key = ats("<key>NSAllowsArbitraryLoads</key><true/>\
             <key>NSAllowsLocalNetworking</key><false/>");
        assert!(!false_key.arbitrary_loads_effective(None));
    }

    #[test]
    fn exception_domains_read_every_key_variant() {
        let ats = ats("<key>NSExceptionDomains</key><dict>\
             <key>example.com</key><dict>\
               <key>NSIncludesSubdomains</key><true/>\
               <key>NSTemporaryExceptionAllowsInsecureHTTPLoads</key><true/>\
               <key>NSThirdPartyExceptionMinimumTLSVersion</key><string>TLSv1.0</string>\
               <key>NSExceptionRequiresForwardSecrecy</key><false/>\
             </dict>\
             <key>localhost</key><dict>\
               <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>\
             </dict>\
             <key>api.example.com</key><dict>\
               <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.2</string>\
               <key>NSExceptionAllowsInsecureHTTPLoads</key><string>YES</string>\
             </dict>\
             </dict>");
        let example = &ats.exception_domains[0];
        assert!(example.includes_subdomains && example.weak_tls());
        assert_eq!(
            example.insecure_http.as_deref(),
            Some("NSTemporaryExceptionAllowsInsecureHTTPLoads")
        );
        assert_eq!(example.requires_forward_secrecy, Some(false));
        assert!(ats.exception_domains[1].is_loopback());
        let api = &ats.exception_domains[2];
        assert!(!api.weak_tls() && api.insecure_http.is_none());
        assert_eq!(
            ats.wrong_types,
            ["NSExceptionDomains/api.example.com/NSExceptionAllowsInsecureHTTPLoads"]
        );
    }
}
