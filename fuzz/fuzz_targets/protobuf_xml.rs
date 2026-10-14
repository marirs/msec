//! aapt2's protobuf XML (app bundle manifests), with the manifest model and checks built on it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::Manifest;
use msec::android::analysis::analyse_manifest;
use msec::android::xml::parse_proto;

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = parse_proto(data) {
        let _ = document.to_xml();
        let manifest = Manifest::from_document(&document);
        let _ = analyse_manifest(&manifest, None);
    }
});
