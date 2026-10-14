//! X.509 certificate decoding (DER), as found in APK signatures.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::signing::certificate::CertificateInfo;

fuzz_target!(|data: &[u8]| {
    let _ = CertificateInfo::from_der(data);
});
