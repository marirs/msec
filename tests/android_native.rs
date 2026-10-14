//! Native library hardening against fixtures written by
//! `tests/fixtures/android/make_elf_fixtures.py`.

use std::io::Cursor;

use msec::android::Apk;
use msec::android::native::{Hardening, PieKind, Relro};
use msec::archive::{Limits, ZipArchive};
use msec::elf::{Class, Elf};

fn library(name: &str) -> Elf {
    let path = format!(
        "{}/tests/fixtures/android/native/{name}.so",
        env!("CARGO_MANIFEST_DIR")
    );
    Elf::parse(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn hardened_library() {
    let elf = library("libhardened");
    assert_eq!(elf.class, Class::Elf64);
    assert_eq!(elf.machine.name(), "AArch64");
    assert_eq!(elf.needed, ["libc.so"]);
    assert_eq!(elf.soname.as_deref(), Some("libhardened.so"));
    let hardening = Hardening::of(&elf);
    assert!(hardening.nx && hardening.stack_canary && hardening.stripped);
    assert_eq!(hardening.pie, PieKind::Dso);
    assert_eq!(hardening.relro, Relro::Full);
    assert_eq!(hardening.fortified, ["__memcpy_chk", "__strlen_chk"]);
    assert!(!hardening.text_relocations && !hardening.debug_info && !hardening.dart);
    assert_eq!(hardening.load_alignment, Some(16384));
    assert!(
        hardening
            .compiler
            .as_deref()
            .unwrap()
            .contains("clang version 17.0.2")
    );
}

#[test]
fn weak_library() {
    let hardening = Hardening::of(&library("libweak"));
    assert!(!hardening.nx, "executable stack");
    assert_eq!(hardening.pie, PieKind::No);
    assert!(!hardening.stack_canary);
    assert_eq!(hardening.relro, Relro::None);
    assert_eq!(hardening.rpath.as_deref(), Some("/data/local/tmp"));
    assert_eq!(hardening.runpath.as_deref(), Some("$ORIGIN/../plugins"));
    assert!(hardening.fortified.is_empty());
    assert!(!hardening.stripped && hardening.debug_info && hardening.text_relocations);
    assert_eq!(hardening.load_alignment, Some(4096));
}

#[test]
fn partial_relro_32_bit_pie() {
    let elf = library("libpartial");
    assert_eq!(elf.class, Class::Elf32);
    let hardening = Hardening::of(&elf);
    assert_eq!(hardening.pie, PieKind::Pie, "ET_DYN with DT_DEBUG");
    assert_eq!(hardening.relro, Relro::Partial);
    assert!(hardening.stack_canary && hardening.fortified.is_empty());
}

#[test]
fn dart_snapshot_is_exempt_like_mobsf() {
    let hardening = Hardening::of(&library("libapp"));
    assert!(hardening.dart && hardening.stack_canary);
    assert_eq!(hardening.relro, Relro::NotApplicable);
}

#[test]
fn symbols_are_found_without_section_headers() {
    let elf = library("libnosections");
    assert!(elf.sections.is_empty());
    let names: Vec<&str> = elf
        .dynamic_symbols
        .iter()
        .map(|symbol| symbol.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["", "__stack_chk_fail", "__read_chk", "hidden_entry"]
    );
    let hardening = Hardening::of(&elf);
    assert!(hardening.stack_canary);
    assert_eq!(hardening.fortified, ["__read_chk"]);
    assert_eq!(hardening.relro, Relro::Full);
}

#[test]
fn apk_native_findings() {
    let bytes = include_bytes!("fixtures/android/native/native.apk");
    let mut archive = ZipArchive::open(Cursor::new(bytes.to_vec()), Limits::default()).unwrap();
    let apk = Apk::read(&mut archive);
    assert_eq!(apk.native_libraries.len(), 5);
    let hardened = apk
        .native_libraries
        .iter()
        .find(|library| library.path.ends_with("libhardened.so"))
        .unwrap();
    assert!(hardened.stored && hardened.data_offset.unwrap() % 16384 == 0);
    assert_eq!(hardened.abi.as_deref(), Some("arm64-v8a"));

    let findings: Vec<(&str, &str, String)> = apk
        .native_findings()
        .iter()
        .map(|finding| {
            let library = finding.library.rsplit('/').next().unwrap();
            let library = if library == "libweak.so" {
                "weak"
            } else if library == "libpartial.so" {
                "partial"
            } else {
                "other"
            };
            (
                library,
                finding.rule.key(),
                finding.detail.clone().unwrap_or_default(),
            )
        })
        .map(|(library, key, detail)| (library, key, detail.replace(char::is_numeric, "#")))
        .collect();
    let expected: Vec<(&str, &str, String)> = [
        ("weak", "elf_nx_missing", ""),
        ("weak", "elf_pie_missing", ""),
        ("weak", "elf_stack_canary_missing", ""),
        ("weak", "elf_relro_missing", ""),
        ("weak", "elf_rpath", "/data/local/tmp"),
        ("weak", "elf_runpath", "$ORIGIN/../plugins"),
        ("weak", "elf_fortify_missing", ""),
        ("weak", "elf_symbols_not_stripped", ""),
        ("weak", "msec_elf_text_relocations", ""),
        ("weak", "msec_elf_debug_info", ""),
        ("weak", "msec_elf_not_16kb_aligned", "# KB pages"),
        (
            "weak",
            "msec_elf_zip_misaligned",
            "offset ##### is not ## KB aligned",
        ),
        ("partial", "elf_relro_partial", ""),
        ("partial", "elf_fortify_missing", ""),
    ]
    .into_iter()
    .map(|(library, key, detail)| (library, key, detail.to_owned()))
    .collect();
    assert_eq!(findings, expected);
}

/// Every single-byte change to the libraries parses or fails without a panic.
#[test]
fn library_mutations_never_panic() {
    for name in ["libhardened", "libweak", "libpartial", "libnosections"] {
        let path = format!(
            "{}/tests/fixtures/android/native/{name}.so",
            env!("CARGO_MANIFEST_DIR")
        );
        let original = std::fs::read(path).unwrap();
        for position in 0..original.len() {
            for replacement in [0x00, 0xff, original[position] ^ 0x80] {
                let mut mutated = original.clone();
                mutated[position] = replacement;
                if let Ok(elf) = Elf::parse(&mutated) {
                    let _ = Hardening::of(&elf);
                }
            }
        }
        for length in 0..original.len() {
            let _ = Elf::parse(&original[..length]);
        }
    }
}
