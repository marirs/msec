//! A whole app bundle read from arbitrary bytes: modules, protobuf manifests, delivery,
//! BundleConfig.pb, the JAR signature, and the base module's manifest and store checks.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use msec::android::Bundle;
use msec::archive::{Limits, ZipArchive};

fuzz_target!(|data: &[u8]| {
    let Ok(mut archive) = ZipArchive::open(Cursor::new(data), Limits::default()) else {
        return;
    };
    let bundle = Bundle::read(&mut archive);
    if let Some(base) = &bundle.base {
        let _ = base.manifest_findings();
        let _ = base.store_findings("2026-10-14");
    }
    let _ = msec::secrets::android::scan_bundle(&mut archive, &bundle);
    let _ = msec::trackers::scan_bundle(&bundle);
    let _ = msec::components::of_bundle(&mut archive, &bundle);
});
