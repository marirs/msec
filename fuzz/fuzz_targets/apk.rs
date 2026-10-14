//! A whole APK read from arbitrary bytes: archive, manifest, resources, network security
//! configuration, signatures (APK Signing Block, v1 PKCS#7), native libraries, DEX files, then
//! every analysis.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use msec::android::Apk;
use msec::archive::{Limits, ZipArchive};

const TODAY: &str = "2026-10-14";

fuzz_target!(|data: &[u8]| {
    let Ok(mut archive) = ZipArchive::open(Cursor::new(data), Limits::default()) else {
        return;
    };
    let apk = Apk::read(&mut archive);
    let _ = apk.manifest_findings();
    let _ = apk.network_findings(TODAY);
    let _ = apk.signing_findings(TODAY);
    let _ = apk.native_findings();
    let _ = apk.store_findings(TODAY);
    let _ = apk.code_summary();
});
