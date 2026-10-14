//! The resource table (`resources.arsc`) decoder.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::ResourceTable;

fuzz_target!(|data: &[u8]| {
    let _ = ResourceTable::parse(data.to_vec());
});
