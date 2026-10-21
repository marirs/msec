//! The plist reader, all three formats (binary, XML, OpenStep text and .strings files), and
//! writing what it read back as XML (which walks every value, including dates and reals).
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::plist::{parse, to_xml};

fuzz_target!(|data: &[u8]| {
    if let Ok(plist) = parse(data) {
        let _ = to_xml(&plist.root);
    }
});
