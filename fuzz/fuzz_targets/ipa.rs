//! The IPA reader: locating the app bundle, its Info.plist and those of its components, and
//! the privacy manifests, on whatever archive libFuzzer makes.
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
    }
});
