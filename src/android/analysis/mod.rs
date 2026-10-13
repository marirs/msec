//! Security analysis of an APK's manifest and network security configuration.
//!
//! Ported from MobSF v4.5.3 `StaticAnalyzer/views/android/manifest_analysis.py`,
//! `network_security.py`, `cert_analysis.py` and `kb/android_manifest_desc.py`. Findings are typed; each carries
//! MobSF's rule key and severity so MobSF-compatible output can be produced. Checks MobSF does
//! not have are marked [`Origin::Msec`]. Deviations are listed in `docs/PORTING.md`.

pub mod manifest_checks;
pub mod network;
pub mod signing_checks;

pub use manifest_checks::{
    ExportReason, ManifestFinding, ManifestRule, PermissionLevel, Protection, analyse_manifest,
};
pub use network::{NetworkFinding, NetworkRule, NetworkSecurityConfig, analyse_network_security};
pub use signing_checks::{SigningFinding, SigningRule, analyse_signing};

/// MobSF's severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// `high`.
    High,
    /// `warning`.
    Warning,
    /// `info`.
    Info,
    /// `secure`: a check that found the safe configuration.
    Secure,
}

impl Severity {
    /// MobSF's name for the level.
    pub fn mobsf_name(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Secure => "secure",
        }
    }
}

/// Where a check comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// Ported from MobSF.
    MobSf,
    /// Added by msec; MobSF-compatible output leaves these out.
    Msec,
}
