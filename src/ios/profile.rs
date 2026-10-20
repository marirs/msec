//! Provisioning profiles (`embedded.mobileprovision`): a CMS SignedData ([`crate::cms`]) whose
//! content is a plist naming the team, the app identifier, the entitlements the app may have,
//! the devices it may run on, the certificates that may sign it, and when it expires.
//!
//! Read as `security cms -D` decodes them (the tests compare the content with its output) and
//! the CMS signature checked like `openssl cms -verify -noverify`: the signature is the signer
//! certificate's, but the chain to Apple's root is not checked. App Store downloads carry no
//! profile; development, ad hoc and enterprise builds do.
//!
//! [`entitlement_mismatches`] approximates what iOS checks at install: every entitlement the
//! app's signature claims must be allowed by the profile (equal, or matched by a trailing `*`).
//! It follows Apple's documented wildcard rule; it has not been checked against a device.

use crate::android::signing::certificate::CertificateInfo;
use crate::cms::{self, CmsError, VerifyProblem};
use crate::plist::date::{CivilTime, absolute_from_civil, civil_from_absolute};
use crate::plist::{self, Dictionary, Plist, PlistError, Value};

/// Why a profile could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// It could not be read from the archive.
    Unreadable(String),
    /// Not CMS SignedData msec can read.
    Cms(CmsError),
    /// The SignedData carries no content (a detached signature).
    NoContent,
    /// The content is not a plist.
    Plist(PlistError),
    /// The plist's top level is not a dictionary.
    NotDictionary,
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(error) => write!(formatter, "the profile cannot be read: {error}"),
            Self::Cms(error) => error.fmt(formatter),
            Self::NoContent => formatter.write_str("the profile's signature carries no content"),
            Self::Plist(error) => write!(formatter, "the profile's content: {error}"),
            Self::NotDictionary => formatter.write_str("the profile's content is not a dictionary"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// How the profile distributes the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileKind {
    /// Development: `get-task-allow`, listed devices.
    Development,
    /// Ad hoc: listed devices, no debugging.
    AdHoc,
    /// Enterprise (in-house): any device (`ProvisionsAllDevices`).
    Enterprise,
    /// App Store: no devices (App Store downloads themselves carry no profile).
    AppStore,
}

impl ProfileKind {
    /// In words.
    pub fn label(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::AdHoc => "ad hoc",
            Self::Enterprise => "enterprise (in-house)",
            Self::AppStore => "App Store",
        }
    }
}

/// The CMS signature over the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSignature {
    /// The signer's certificate, when found.
    pub signer: Option<CertificateInfo>,
    /// Every certificate the signature carries.
    pub certificates: Vec<CertificateInfo>,
    /// Whether the signer's signature verifies over the content (chain not checked).
    pub verified: Result<(), VerifyProblem>,
}

/// A provisioning profile.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvisioningProfile {
    /// The CMS signature.
    pub signature: ProfileSignature,
    /// The content, read as iOS reads plists.
    pub plist: Plist,
    /// `Name`.
    pub name: Option<String>,
    /// `UUID`.
    pub uuid: Option<String>,
    /// `TeamIdentifier`.
    pub team_identifiers: Vec<String>,
    /// `TeamName`.
    pub team_name: Option<String>,
    /// `AppIDName`.
    pub app_id_name: Option<String>,
    /// `Platform`.
    pub platforms: Vec<String>,
    /// `CreationDate` (absolute time).
    pub creation_date: Option<f64>,
    /// `ExpirationDate` (absolute time).
    pub expiration_date: Option<f64>,
    /// `ProvisionedDevices` (UDIDs).
    pub provisioned_devices: Vec<String>,
    /// `ProvisionsAllDevices`.
    pub provisions_all_devices: bool,
    /// `DeveloperCertificates`: the certificates allowed to sign the app.
    pub developer_certificates: Vec<CertificateInfo>,
    /// `IsXcodeManaged`.
    pub xcode_managed: Option<bool>,
}

impl ProvisioningProfile {
    /// Reads a profile: the CMS signature, then its content.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let signed = cms::parse(bytes).map_err(ProfileError::Cms)?;
        let content = signed.content.clone().ok_or(ProfileError::NoContent)?;
        let certificates: Vec<CertificateInfo> = signed
            .certificates
            .iter()
            .filter_map(|der| CertificateInfo::from_der(der).ok())
            .collect();
        let (signer, verified) = match signed.signers.first() {
            None => (None, Err(VerifyProblem::NoCertificate)),
            Some(signer) => match signed.verify(signer, &content) {
                Ok((certificate, _)) => (Some(certificate), Ok(())),
                Err(problem) => (
                    signed
                        .signer_certificate(signer)
                        .and_then(|der| CertificateInfo::from_der(der).ok()),
                    Err(problem),
                ),
            },
        };
        let plist = plist::parse(&content).map_err(ProfileError::Plist)?;
        let dictionary = plist
            .root
            .as_dictionary()
            .ok_or(ProfileError::NotDictionary)?;
        let string = |key: &str| {
            dictionary
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let strings = |key: &str| -> Vec<String> {
            dictionary
                .get(key)
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        };
        let date = |key: &str| match dictionary.get(key) {
            Some(Value::Date(absolute)) => Some(*absolute),
            _ => None,
        };
        let developer_certificates = dictionary
            .get("DeveloperCertificates")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|value| match value {
                Value::Data(der) => CertificateInfo::from_der(der).ok(),
                _ => None,
            })
            .collect();
        Ok(Self {
            signature: ProfileSignature {
                signer,
                certificates,
                verified,
            },
            name: string("Name"),
            uuid: string("UUID"),
            team_identifiers: strings("TeamIdentifier"),
            team_name: string("TeamName"),
            app_id_name: string("AppIDName"),
            platforms: strings("Platform"),
            creation_date: date("CreationDate"),
            expiration_date: date("ExpirationDate"),
            provisioned_devices: strings("ProvisionedDevices"),
            provisions_all_devices: dictionary
                .get("ProvisionsAllDevices")
                .and_then(Value::as_bool)
                == Some(true),
            developer_certificates,
            xcode_managed: dictionary.get("IsXcodeManaged").and_then(Value::as_bool),
            plist,
        })
    }

    /// The entitlements the profile allows.
    pub fn entitlements(&self) -> Option<&Dictionary> {
        self.plist.root.get("Entitlements")?.as_dictionary()
    }

    /// The application identifier it provisions (`TEAMID.dev.example.app` or `TEAMID.*`).
    pub fn application_identifier(&self) -> Option<&str> {
        self.entitlements()?.get("application-identifier")?.as_str()
    }

    /// How it distributes the app.
    pub fn kind(&self) -> ProfileKind {
        let debuggable = self
            .entitlements()
            .and_then(|entitlements| entitlements.get("get-task-allow"))
            .and_then(Value::as_bool)
            == Some(true);
        if self.provisions_all_devices {
            ProfileKind::Enterprise
        } else if debuggable {
            ProfileKind::Development
        } else if !self.provisioned_devices.is_empty() {
            ProfileKind::AdHoc
        } else {
            ProfileKind::AppStore
        }
    }

    /// `ExpirationDate` as `yyyy-MM-dd` (UTC).
    pub fn expires_on(&self) -> Option<String> {
        day_of(self.expiration_date?)
    }

    /// `CreationDate` as `yyyy-MM-dd` (UTC).
    pub fn created_on(&self) -> Option<String> {
        day_of(self.creation_date?)
    }

    /// The profile has expired by `today` (`yyyy-MM-dd`, start of day UTC); `None` without an
    /// expiration date or with an unreadable `today`.
    pub fn expired(&self, today: &str) -> Option<bool> {
        Some(self.expiration_date? <= absolute_day(today)?)
    }

    /// Whether the profile provisions the bundle identifier: its application identifier is
    /// `<prefix>.<bundle identifier>`, or ends in `*` and the rest matches.
    pub fn covers_bundle(&self, bundle_identifier: &str) -> Option<bool> {
        let application = self.application_identifier()?;
        let (_, pattern) = application.split_once('.')?;
        Some(wildcard_match(pattern, bundle_identifier))
    }
}

/// `yyyy-MM-dd` (UTC) of an absolute time.
fn day_of(absolute: f64) -> Option<String> {
    let time = civil_from_absolute(absolute)?;
    Some(format!(
        "{:04}-{:02}-{:02}",
        time.year, time.month, time.day
    ))
}

/// Absolute time of the start of `today` (`yyyy-MM-dd`).
fn absolute_day(today: &str) -> Option<f64> {
    let mut parts = today.split('-');
    let mut next = || parts.next()?.parse::<i64>().ok();
    let (year, month, day) = (next()?, next()?, next()?);
    absolute_from_civil(CivilTime {
        year,
        month,
        day,
        hour: 0,
        minute: 0,
        second: 0,
    })
}

/// A profile value's trailing `*` matches any rest; otherwise the values are equal.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

/// An app entitlement the profile does not allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementMismatch {
    /// The entitlement.
    pub key: String,
    /// Why, in words.
    pub reason: String,
}

/// The entitlements in `app` (from the code signature) that `profile` does not allow.
pub fn entitlement_mismatches(profile: &Dictionary, app: &Dictionary) -> Vec<EntitlementMismatch> {
    let mut mismatches = Vec::new();
    for (key, value) in app.iter() {
        let Some(allowed) = profile.get(key) else {
            mismatches.push(EntitlementMismatch {
                key: key.to_owned(),
                reason: "not in the provisioning profile".to_owned(),
            });
            continue;
        };
        if !allows(allowed, value) {
            mismatches.push(EntitlementMismatch {
                key: key.to_owned(),
                reason: format!(
                    "the profile allows {}, the app claims {}",
                    describe(allowed),
                    describe(value)
                ),
            });
        }
    }
    mismatches
}

/// Whether a profile value allows an app value.
fn allows(allowed: &Value, claimed: &Value) -> bool {
    match (allowed, claimed) {
        // A true flag in the profile allows true or false; false allows only false.
        (Value::Boolean(allowed), Value::Boolean(claimed)) => *allowed || !*claimed,
        (Value::String(pattern), Value::String(value)) => wildcard_match(pattern, value),
        (Value::Array(patterns), Value::String(value)) => patterns
            .iter()
            .filter_map(Value::as_str)
            .any(|pattern| wildcard_match(pattern, value)),
        (allowed, Value::Array(values)) => values.iter().all(|value| allows(allowed, value)),
        (allowed, claimed) => allowed == claimed,
    }
}

fn describe(value: &Value) -> String {
    match value {
        Value::String(text) => format!("\"{text}\""),
        Value::Boolean(flag) => flag.to_string(),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(describe).collect::<Vec<_>>().join(", ")
        ),
        other => other.type_name().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dictionary(xml: &str) -> Dictionary {
        let document = format!("<plist><dict>{xml}</dict></plist>");
        match plist::parse(document.as_bytes()).unwrap().root {
            Value::Dictionary(dictionary) => dictionary,
            _ => unreachable!(),
        }
    }

    #[test]
    fn entitlements_match_with_trailing_wildcards() {
        let profile = dictionary(
            "<key>application-identifier</key><string>A1B2C3D4E5.*</string>\
             <key>keychain-access-groups</key><array><string>A1B2C3D4E5.*</string></array>\
             <key>get-task-allow</key><false/>",
        );
        let allowed = dictionary(
            "<key>application-identifier</key><string>A1B2C3D4E5.dev.app</string>\
             <key>keychain-access-groups</key><array><string>A1B2C3D4E5.dev.app</string></array>\
             <key>get-task-allow</key><false/>",
        );
        assert_eq!(entitlement_mismatches(&profile, &allowed), []);
        let claimed = dictionary(
            "<key>application-identifier</key><string>Z9.dev.app</string>\
             <key>get-task-allow</key><true/>\
             <key>com.apple.developer.icloud-services</key><array><string>CloudKit</string></array>",
        );
        let keys: Vec<String> = entitlement_mismatches(&profile, &claimed)
            .into_iter()
            .map(|mismatch| mismatch.key)
            .collect();
        assert_eq!(
            keys,
            [
                "application-identifier",
                "get-task-allow",
                "com.apple.developer.icloud-services"
            ]
        );
        assert!(wildcard_match("dev.*", "dev.app"));
        assert!(!wildcard_match("dev.app", "dev.app2"));
        assert_eq!(absolute_day("2001-01-01"), Some(0.0));
    }
}
