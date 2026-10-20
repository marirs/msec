//! Provisioning profiles: the CMS SignedData reader (BER and DER), signature verification, the
//! plist content, and the profile's fields, expiry and bundle matching.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::ios::profile::ProvisioningProfile;

fuzz_target!(|data: &[u8]| {
    if let Ok(profile) = ProvisioningProfile::parse(data) {
        let _ = profile.kind();
        let _ = profile.expired("2026-10-20");
        let _ = profile.expires_on();
        let _ = profile.covers_bundle("dev.appchk.fixture");
    }
});
