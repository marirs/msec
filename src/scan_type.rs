//! Package kinds accepted for analysis, recognised from the file extension.
//!
//! Ported from `ANDROID_EXTS`, `IOS_EXTS` and `WINDOWS_EXTS` in MobSF `mobsf/MobSF/settings.py`
//! (v4.5.3), together with the magic-byte check each kind must pass before analysis.

use std::path::Path;

use crate::magic;

/// Target platform of a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Android packages and libraries.
    Android,
    /// iOS packages and libraries.
    Ios,
    /// Windows APPX packages (recognised, not analysed by msec).
    Windows,
}

/// A package kind MobSF accepts for analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanType {
    /// Android application package.
    Apk,
    /// APK bundle with OBB data (`.xapk`).
    Xapk,
    /// Split APK set (`.apks`).
    Apks,
    /// Android App Bundle.
    Aab,
    /// Java archive.
    Jar,
    /// Android library archive.
    Aar,
    /// Android native shared library (ELF).
    So,
    /// Zipped Android or iOS source project.
    Zip,
    /// iOS application archive.
    Ipa,
    /// iOS dynamic library (Mach-O).
    Dylib,
    /// iOS static library.
    A,
    /// Windows application package. Recognised for completeness; msec does not port MobSF's
    /// Windows analyzer.
    Appx,
}

/// Why a file cannot be analysed as a given [`ScanType`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// The extension is not one MobSF accepts.
    UnknownExtension(String),
    /// The leading bytes do not match the signature required for the scan type.
    MagicMismatch(ScanType),
}

impl std::fmt::Display for UnsupportedReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownExtension(extension) => {
                write!(formatter, "unsupported file extension {extension:?}")
            }
            Self::MagicMismatch(scan_type) => write!(
                formatter,
                "file content does not match the {} signature",
                scan_type.extension()
            ),
        }
    }
}

impl std::error::Error for UnsupportedReason {}

impl ScanType {
    /// Every accepted scan type, in MobSF's declaration order.
    pub const ALL: [ScanType; 12] = [
        Self::Apk,
        Self::Xapk,
        Self::Apks,
        Self::Zip,
        Self::Aab,
        Self::So,
        Self::Jar,
        Self::Aar,
        Self::Ipa,
        Self::Dylib,
        Self::A,
        Self::Appx,
    ];

    /// Lower-case file extension without the dot, as MobSF lists it.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Apk => "apk",
            Self::Xapk => "xapk",
            Self::Apks => "apks",
            Self::Aab => "aab",
            Self::Jar => "jar",
            Self::Aar => "aar",
            Self::So => "so",
            Self::Zip => "zip",
            Self::Ipa => "ipa",
            Self::Dylib => "dylib",
            Self::A => "a",
            Self::Appx => "appx",
        }
    }

    /// Platform the scan type belongs to. A source `.zip` is listed under Android upstream;
    /// whether it holds an Android or iOS project is decided later from its contents.
    pub fn platform(self) -> Platform {
        match self {
            Self::Apk
            | Self::Xapk
            | Self::Apks
            | Self::Aab
            | Self::Jar
            | Self::Aar
            | Self::So
            | Self::Zip => Platform::Android,
            Self::Ipa | Self::Dylib | Self::A => Platform::Ios,
            Self::Appx => Platform::Windows,
        }
    }

    /// Recognises the scan type from a file extension (with or without the leading dot,
    /// case-insensitive).
    pub fn from_extension(extension: &str) -> Result<Self, UnsupportedReason> {
        let normalized = extension.trim_start_matches('.').to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|scan_type| scan_type.extension() == normalized)
            .ok_or(UnsupportedReason::UnknownExtension(normalized))
    }

    /// Recognises the scan type from a file name or path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, UnsupportedReason> {
        let extension = path
            .as_ref()
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        Self::from_extension(extension)
    }

    /// True when `leading_bytes` carry the signature this scan type requires. ZIP-based kinds
    /// need a ZIP local file header, `.so` needs ELF, `.dylib` needs Mach-O or fat, `.a` needs
    /// `!<ar` or fat.
    pub fn matches_magic(self, leading_bytes: &[u8]) -> bool {
        match self {
            Self::So => magic::is_elf(leading_bytes),
            Self::Dylib => magic::is_dylib(leading_bytes),
            Self::A => magic::is_static_library(leading_bytes),
            Self::Apk
            | Self::Xapk
            | Self::Apks
            | Self::Aab
            | Self::Jar
            | Self::Aar
            | Self::Zip
            | Self::Ipa
            | Self::Appx => magic::is_zip(leading_bytes),
        }
    }

    /// Recognises the scan type from the file name and verifies its leading bytes.
    pub fn detect(path: impl AsRef<Path>, leading_bytes: &[u8]) -> Result<Self, UnsupportedReason> {
        let scan_type = Self::from_path(path)?;
        if scan_type.matches_magic(leading_bytes) {
            Ok(scan_type)
        } else {
            Err(UnsupportedReason::MagicMismatch(scan_type))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_are_case_insensitive_and_dot_tolerant() {
        assert_eq!(ScanType::from_extension("APK"), Ok(ScanType::Apk));
        assert_eq!(ScanType::from_extension(".ipa"), Ok(ScanType::Ipa));
        assert_eq!(
            ScanType::from_extension("exe"),
            Err(UnsupportedReason::UnknownExtension("exe".to_owned()))
        );
    }

    #[test]
    fn every_scan_type_round_trips_through_its_extension() {
        for scan_type in ScanType::ALL {
            assert_eq!(
                ScanType::from_extension(scan_type.extension()),
                Ok(scan_type)
            );
        }
    }

    #[test]
    fn platforms_follow_upstream_extension_lists() {
        assert_eq!(ScanType::Aab.platform(), Platform::Android);
        assert_eq!(ScanType::Zip.platform(), Platform::Android);
        assert_eq!(ScanType::A.platform(), Platform::Ios);
        assert_eq!(ScanType::Appx.platform(), Platform::Windows);
    }

    #[test]
    fn detect_rejects_content_that_does_not_match_the_extension() {
        assert_eq!(
            ScanType::detect("app.apk", b"PK\x03\x04..."),
            Ok(ScanType::Apk)
        );
        assert_eq!(
            ScanType::detect("libnative.so", b"PK\x03\x04..."),
            Err(UnsupportedReason::MagicMismatch(ScanType::So))
        );
        assert_eq!(
            ScanType::detect("Payload.IPA", b"\x7FELF"),
            Err(UnsupportedReason::MagicMismatch(ScanType::Ipa))
        );
        assert!(ScanType::detect("no-extension", b"PK\x03\x04").is_err());
    }
}
