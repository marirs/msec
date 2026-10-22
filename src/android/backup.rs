//! Backup rules: the files the manifest names in `android:fullBackupContent` (Android 11 and
//! lower, and Android 12+ apps targeting API 30 or lower) and `android:dataExtractionRules`
//! (Android 12+ apps targeting API 31 or higher), read as Android reads them: which domains
//! and paths each mode includes or excludes, and whether cloud backup requires end-to-end
//! encryption. msec origin: MobSF reports `allowBackup` only.
//!
//! What a rule file means for an app depends on its target API and the device's release, and
//! whether the files it keeps out hold sensitive data is not established here.

use super::value::Value;
use super::xml::{XmlDocument, XmlElement};

/// Which manifest attribute named the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackupRulesSource {
    /// `android:fullBackupContent`.
    FullBackupContent,
    /// `android:dataExtractionRules`.
    DataExtractionRules,
}

/// One rule file, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRules {
    /// The attribute that names it.
    pub source: BackupRulesSource,
    /// The file in the package (`res/xml/backup_rules.xml`).
    pub path: String,
    /// Each mode it configures, in file order.
    pub modes: Vec<BackupMode>,
}

/// One mode: `full-backup-content` (the whole of a `fullBackupContent` file), or
/// `cloud-backup`, `device-transfer` or `cross-platform-transfer` of a `dataExtractionRules`
/// file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupMode {
    /// The element's name.
    pub mode: String,
    /// `disableIfNoEncryptionCapabilities` on `cloud-backup`: backups only with end-to-end
    /// encryption. `None` when not set.
    pub requires_encryption: Option<bool>,
    /// `<include>` rules, in file order. None means everything is included, except what is
    /// excluded.
    pub includes: Vec<BackupPath>,
    /// `<exclude>` rules, in file order.
    pub excludes: Vec<BackupPath>,
}

/// One `<include>` or `<exclude>`: a domain (`file`, `database`, `sharedpref`, `external`,
/// `root`, and the device-protected variants) and a path in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPath {
    /// `domain`.
    pub domain: String,
    /// `path` (`.` is the whole domain).
    pub path: String,
}

impl BackupRules {
    /// The rule file at `path`, named by `source`, from its decoded document.
    pub fn from_document(source: BackupRulesSource, path: &str, document: &XmlDocument) -> Self {
        let modes = match (&document.root, source) {
            (Some(root), BackupRulesSource::FullBackupContent)
                if root.name == "full-backup-content" =>
            {
                vec![mode_of(root)]
            }
            (Some(root), BackupRulesSource::DataExtractionRules)
                if root.name == "data-extraction-rules" =>
            {
                root.elements()
                    .filter(|element| {
                        matches!(
                            element.name.as_str(),
                            "cloud-backup" | "device-transfer" | "cross-platform-transfer"
                        )
                    })
                    .map(mode_of)
                    .collect()
            }
            _ => Vec::new(),
        };
        Self {
            source,
            path: path.to_owned(),
            modes,
        }
    }
}

fn mode_of(element: &XmlElement) -> BackupMode {
    let rules = |name: &str| -> Vec<BackupPath> {
        element
            .elements_named(name)
            .map(|rule| BackupPath {
                domain: text(rule.plain_attribute("domain")),
                path: text(rule.plain_attribute("path")),
            })
            .collect()
    };
    BackupMode {
        mode: element.name.clone(),
        requires_encryption: element
            .plain_attribute("disableIfNoEncryptionCapabilities")
            .and_then(Value::as_bool),
        includes: rules("include"),
        excludes: rules("exclude"),
    }
}

fn text(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_str)
        .map_or_else(String::new, str::to_owned)
}
