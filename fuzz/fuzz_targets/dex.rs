//! The DEX reader: every logical file of a container, and every string, type, class,
//! superclass, interface and source file it resolves.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::dex::parse;

fuzz_target!(|data: &[u8]| {
    let container = parse(data);
    let _ = container.complete();
    for file in &container.files {
        let _ = file.strings().flatten().map(str::len).sum::<usize>();
        let _ = file.compiler_markers().count();
        for class in &file.classes {
            let _ = file.class_descriptor(class);
            let _ = file.superclass(class);
            let _ = file.source_file(class);
            let _ = file.interfaces(class).flatten().count();
        }
    }
});
