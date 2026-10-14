//! The ELF parser and the hardening computed from it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::native::Hardening;
use msec::elf::Elf;

fuzz_target!(|data: &[u8]| {
    if let Ok(elf) = Elf::parse(data) {
        let _ = Hardening::of(&elf);
    }
});
