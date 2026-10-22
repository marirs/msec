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
pub mod ats;
mod binaries;
pub mod coverage;
pub mod distribution;
mod info;
mod ipa;
pub mod privacy;
pub mod profile;
pub mod purpose_strings;
pub mod required_reason;
pub mod store_leads;
pub mod upload_requirements;

pub use binaries::{BinaryRole, BundleBinary, SignatureCheck, SignatureKind};

/// The associated domains the main executable's entitlements list
/// (`com.apple.developer.associated-domains`: `applinks:example.com`, `webcredentials:...`), as
/// written; empty when it lists none or its entitlements could not be read.
pub fn associated_domains(app: &AppBundle) -> Vec<String> {
    app.binaries
        .first()
        .and_then(BundleBinary::entitlements)
        .and_then(|plist| plist.as_ref().ok())
        .and_then(|plist| plist.root.as_dictionary())
        .and_then(|entitlements| entitlements.get("com.apple.developer.associated-domains"))
        .and_then(crate::plist::Value::as_array)
        .map(|domains| {
            domains
                .iter()
                .filter_map(|domain| domain.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
pub use info::{BundleInfo, WrongType};
pub use ipa::{AppBundle, BundleComponent, ComponentKind, Ipa, IpaProblem, LocalizedInfo};
pub use privacy::{AccessedApiType, CollectedDataType, PrivacyManifest};
