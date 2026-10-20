//! aapt2's protobuf resource table (`resources.pb` in app bundles), with the lookups the
//! manifest and network security configuration use.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::ResourceTable;

fuzz_target!(|data: &[u8]| {
    if let Ok(table) = ResourceTable::parse_proto(data) {
        let _ = table.locales();
        let _ = table.package_names();
        for id in [0x7f01_0000, 0x7f02_0000, 0x7f03_0001, 0x0000_0000] {
            let _ = table.name(id);
            let _ = table.resolve(id);
            let _ = table.files(id);
        }
        let _ = table.find("string", "app_name");
    }
});
