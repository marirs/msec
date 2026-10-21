//! The IPA reader: locating the app bundle, its Info.plist and those of its components, and
//! the privacy manifests, then the analysis (signers, entitlements, profile, ATS, privacy
//! manifests and required-reason APIs, purpose strings, tracking and upload requirements),
//! what it could not check (encrypted executables, unverified signers, unrecorded build keys)
//! and the secret and tracker scans, on whatever archive libFuzzer makes.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;

fuzz_target!(|data: &[u8]| {
    let Ok(mut archive) = ZipArchive::open(Cursor::new(data), Limits::default()) else {
        return;
    };
    let ipa = Ipa::read(&mut archive);
    if let Some(app) = &ipa.app {
        let _ = app.components.len() + app.privacy_manifests.len();
        let _ = ipa.problems.iter().filter(|problem| problem.rejected_by_ios()).count();
        let _ = msec::ios::analysis::analyse_binaries(app);
        let _ = msec::ios::analysis::analyse_app(app, "2026-10-21");
        let _ = msec::ios::coverage::unchecked(app);
    }
    let _ = msec::secrets::ios::scan_ipa(&mut archive, &ipa);
    let _ = msec::trackers::scan_ipa(&mut archive, &ipa);
    let _ = msec::components::of_ipa(&ipa);
});
