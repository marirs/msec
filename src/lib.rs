//! # msec
//!
//! Mobile app security analysis core for Android and iOS packages, ported to Rust from the
//! analysis engine of [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
//! (Mobile Security Framework). Only the analysis core is ported; MobSF's web UI, REST API,
//! database and user management are out of scope.
//!
//! **Status: early development.** This release contains the scan-input layer:
//!
//! - [`ScanType`]: the package kinds MobSF accepts, recognised from the file extension.
//! - [`magic`]: the magic-byte checks MobSF applies before analysing an upload.
//! - [`FileHashes`]: the MD5 (MobSF's scan identifier), SHA-1 and SHA-256 of a package.
//! - [`archive`]: a safe, bounded ZIP reader for packages that never extracts to disk and
//!   reports structural anomalies (including those Android itself rejects).
//! - [`android::Inventory`]: what an Android package contains: composition, DEX files, native
//!   libraries per ABI, and the frameworks they reveal (Flutter, React Native, Unity, ...).
//! - [`android::Apk`]: the manifest and resource table decoded the way Android decodes them
//!   ([`android::xml`], [`android::resources`], [`android::manifest`]), with framework
//!   permission and SDK level data.
//!
//! Android manifest, certificate, network-security-config and binary analysis follow in the
//! next releases. See the repository README for the porting roadmap.
//!
//! msec is an independent port and is not affiliated with or endorsed by the MobSF project.

pub mod android;
pub mod archive;
pub mod hashes;
pub mod magic;
pub mod scan_type;

pub use hashes::FileHashes;
pub use scan_type::{Platform, ScanType, UnsupportedReason};
