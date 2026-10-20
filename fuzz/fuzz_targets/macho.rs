//! The Mach-O reader: thin and universal files, every load command, the symbol table, the code
//! signature (CodeDirectories, entitlements), hardening, and page-hash verification.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::macho::{Hardening, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(file) = parse(data) else {
        return;
    };
    for slice in &file.slices {
        let _ = slice.architecture();
        let Ok(image) = &slice.image else {
            continue;
        };
        let _ = Hardening::of(image);
        if let Some(Ok(signature)) = &image.signature {
            for directory in &signature.code_directories {
                let _ = directory.cdhash();
                let _ = directory.special_slot(1);
                // Slice bytes: the whole input for a thin file.
                let start = slice.offset as usize;
                if let Some(bytes) = data.get(start..start.saturating_add(slice.size as usize)) {
                    let _ = directory.verify_pages(bytes);
                }
            }
        }
    }
});
