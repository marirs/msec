//! The DEX reader: every logical file of a container, every string, type, class, superclass,
//! interface and source file it resolves, method and field signatures, and the code scan.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::android::dex::parse;

fuzz_target!(|data: &[u8]| {
    let container = parse(data);
    let _ = container.complete();
    for file in &container.files {
        let _ = file.strings().flatten().map(str::len).sum::<usize>();
        let _ = file.compiler_markers().count();
        for reference in file.references() {
            let _ = file.method_signature(reference.caller);
        }
        for method in 0..file.method_count() as u32 {
            let _ = file.method_signature(method);
        }
        for field in 0..file.field_count() as u32 {
            let _ = file.field_signature(field);
        }
        for class in &file.classes {
            let _ = file.class_descriptor(class);
            let _ = file.superclass(class);
            let _ = file.source_file(class);
            let _ = file.interfaces(class).flatten().count();
        }
    }
});
