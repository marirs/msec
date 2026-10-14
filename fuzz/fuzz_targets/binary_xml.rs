//! The binary XML decoder, then the models built from a document: the manifest and the network
//! security configuration, and the manifest checks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::Manifest;
use msec::android::analysis::{NetworkSecurityConfig, analyse_manifest};

fuzz_target!(|data: &[u8]| {
    let Ok(document) = msec::android::xml::parse(data) else {
        return;
    };
    let manifest = Manifest::from_document(&document);
    let _ = analyse_manifest(&manifest, None);
    let _ = NetworkSecurityConfig::from_document(&document, None);
});
