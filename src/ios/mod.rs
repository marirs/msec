//! iOS packages (IPA): the app bundle inside `Payload/`, its `Info.plist`, and what the bundle
//! carries (frameworks, app extensions, watch apps, App Clips, privacy manifests, the
//! provisioning profile, the code signature's resource seal, FairPlay metadata).
//!
//! MobSF's `ipa.py` extracts the IPA to disk, takes the first `*.app` under a `Payload/`
//! directory at any depth, and reads `Info.plist` with Python's `plistlib`. msec reads the
//! archive in place, prefers `Payload/<name>.app/` at the archive root as the App Store expects
//! it and records any other layout as an [`IpaProblem`], and reads plists the way iOS does
//! ([`crate::plist`]). Every bundle's executable is read as Mach-O ([`crate::macho`]) and its
//! code signature checked against the bundle's files ([`BundleBinary`]); see
//! `docs/PORTING.md`.

pub mod analysis;
mod binaries;
mod info;
mod ipa;

pub use binaries::{BinaryRole, BundleBinary, SignatureCheck, SignatureKind};
pub use info::{BundleInfo, WrongType};
pub use ipa::{AppBundle, BundleComponent, ComponentKind, Ipa, IpaProblem, PrivacyManifest};
