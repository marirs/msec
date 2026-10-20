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
//! - [`android::signing`]: v1/v2/v3/v3.1 signature verification and signer certificates.
//! - [`elf`] and [`android::native`]: native libraries and their hardening.
//! - [`android::dex`]: DEX files (compiled code) in the order Android loads them: strings,
//!   types, class definitions and what each method's code refers to, with the structural
//!   problems ART rejects; [`android::api`] and `analysis::code_checks` judge those references
//!   (deprecated and removed framework APIs, Google Play's code checks).
//! - [`android::Bundle`]: Android App Bundles, module by module: manifests in aapt2's protobuf
//!   XML ([`android::xml::parse_proto`]), resource tables (`resources.pb`,
//!   [`android::ResourceTable::parse_proto`]), DEX files and native libraries, with the base
//!   module readable as an APK by every check.
//!
//! - [`plist`]: property lists, binary and XML, read with Core Foundation's rules (duplicate
//!   keys, nesting limits, number and date parsing), checked against `plutil`.
//! - [`ios::Ipa`]: iOS packages: the app bundle, `Info.plist`, embedded frameworks, app
//!   extensions and privacy manifests.
//!
//! - [`macho`]: Mach-O files (thin and universal): load commands, symbols, hardening, and code
//!   signatures with page and special-slot hash verification; every executable of an IPA is
//!   read this way.
//!
//! See the repository README for the porting roadmap.
//!
//! msec is an independent port and is not affiliated with or endorsed by the MobSF project.

pub mod android;
pub mod archive;
pub mod elf;
pub mod hashes;
pub mod ios;
pub mod macho;
pub mod magic;
pub mod plist;
pub mod scan_type;

pub use hashes::FileHashes;
pub use scan_type::{Platform, ScanType, UnsupportedReason};
