//! The ZIP reader on arbitrary bytes: open (central directory, end records, anomalies), then
//! every entry through the entry reader and inflater, within the default limits.
#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use msec::archive::{Limits, ZipArchive};

fuzz_target!(|data: &[u8]| {
    let Ok(mut archive) = ZipArchive::open(Cursor::new(data), Limits::default()) else {
        return;
    };
    for index in 0..archive.entries().len() {
        let _ = archive.read(index);
    }
});
