//! ELF parsing cross-checked against the `object` crate, an independent parser.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use msec::archive::{Limits, ZipArchive};
use msec::elf::{Class, Elf, ElfKind};
use object::read::elf::{Dyn, ElfFile, FileHeader, ProgramHeader};
use object::{Object, ObjectSection, ObjectSymbol};

/// `(p_type, p_flags, p_align)` per program header.
type Segments = Vec<(u32, u32, u64)>;
/// `(tag, value)` per dynamic entry.
type Dynamic = Vec<(i64, u64)>;

/// What both parsers must agree on.
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    is_64: bool,
    kind: &'static str,
    segments: Vec<(u32, u32, u64)>,
    dynamic: Vec<(i64, u64)>,
    dynamic_symbols: BTreeSet<String>,
    static_symbols: BTreeSet<String>,
    sections: Vec<String>,
}

fn msec_summary(bytes: &[u8]) -> Summary {
    let elf = Elf::parse(bytes).unwrap();
    Summary {
        is_64: elf.class == Class::Elf64,
        kind: match elf.kind {
            ElfKind::Shared => "dynamic",
            ElfKind::Executable => "executable",
            ElfKind::Relocatable => "relocatable",
            _ => "other",
        },
        segments: elf
            .segments
            .iter()
            .map(|segment| (segment.kind, segment.flags, segment.align))
            .collect(),
        dynamic: elf.dynamic.clone(),
        dynamic_symbols: elf
            .dynamic_symbols
            .iter()
            .map(|symbol| symbol.name.clone())
            .filter(|name| !name.is_empty())
            .collect(),
        static_symbols: elf
            .static_symbols
            .iter()
            .filter(|name| !name.is_empty())
            .cloned()
            .collect(),
        // `object` leaves out the null section at index 0.
        sections: elf
            .sections
            .iter()
            .skip(1)
            .map(|section| section.name.clone())
            .collect(),
    }
}

fn object_summary(bytes: &[u8]) -> Summary {
    let file = object::File::parse(bytes).unwrap();
    let (segments, dynamic) = if file.is_64() {
        elf_details::<object::elf::FileHeader64<object::Endianness>>(bytes)
    } else {
        elf_details::<object::elf::FileHeader32<object::Endianness>>(bytes)
    };
    let names = |symbols: Vec<String>| {
        symbols
            .into_iter()
            .filter(|name| !name.is_empty())
            .collect()
    };
    Summary {
        is_64: file.is_64(),
        kind: match file.kind() {
            object::ObjectKind::Dynamic => "dynamic",
            object::ObjectKind::Executable => "executable",
            object::ObjectKind::Relocatable => "relocatable",
            _ => "other",
        },
        segments,
        dynamic,
        dynamic_symbols: names(
            file.dynamic_symbols()
                .map(|symbol| symbol.name().unwrap_or_default().to_owned())
                .collect(),
        ),
        static_symbols: names(
            file.symbols()
                .map(|symbol| symbol.name().unwrap_or_default().to_owned())
                .collect(),
        ),
        sections: file
            .sections()
            .map(|section| section.name().unwrap_or_default().to_owned())
            .collect(),
    }
}

fn elf_details<Header: FileHeader<Endian = object::Endianness>>(
    bytes: &[u8],
) -> (Segments, Dynamic) {
    let file = ElfFile::<Header>::parse(bytes).unwrap();
    let endian = file.endian();
    let headers = file.elf_program_headers();
    let segments = headers
        .iter()
        .map(|header| {
            (
                header.p_type(endian).0,
                header.p_flags(endian).0,
                header.p_align(endian).into(),
            )
        })
        .collect();
    let dynamic = headers
        .iter()
        .find_map(|header| header.dynamic(endian, bytes).ok().flatten())
        .map(|entries| {
            entries
                .iter()
                .map(|entry| (entry.d_tag(endian).0, entry.d_val(endian).into()))
                .take_while(|(tag, _)| *tag != 0)
                .collect()
        })
        .unwrap_or_default();
    (segments, dynamic)
}

/// `.so` files inside AARs in the local Gradle cache: real NDK output (WebRTC, SQLCipher,
/// MediaPipe, ...). Used only when present; nothing third-party is committed.
fn local_android_libraries(limit: usize) -> Vec<(String, Vec<u8>)> {
    let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_default();
    let mut aars = Vec::new();
    collect_aars(
        &home.join(".gradle/caches/modules-2/files-2.1"),
        6,
        &mut aars,
    );
    aars.sort();
    let mut libraries = Vec::new();
    for aar in aars {
        let Ok(mut archive) = ZipArchive::open_path(&aar, Limits::default()) else {
            continue;
        };
        let names: Vec<String> = archive
            .entries()
            .iter()
            .map(|entry| entry.name.clone())
            .filter(|name| name.starts_with("jni/") && name.ends_with(".so"))
            .collect();
        for name in names {
            if let Ok(Some(bytes)) = archive.read_by_name(&name) {
                libraries.push((format!("{}!{name}", aar.display()), bytes));
            }
            if libraries.len() >= limit {
                return libraries;
            }
        }
    }
    libraries
}

fn collect_aars(directory: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && depth > 0 {
            collect_aars(&path, depth - 1, out);
        } else if path.extension().is_some_and(|extension| extension == "aar") {
            out.push(path);
        }
    }
}

#[test]
fn real_android_libraries_parse_like_object() {
    let libraries = local_android_libraries(60);
    if libraries.is_empty() {
        eprintln!("no Android native libraries in the Gradle cache; skipping");
        return;
    }
    for (name, bytes) in &libraries {
        let ours = msec_summary(bytes);
        let theirs = object_summary(bytes);
        assert_eq!(ours.is_64, theirs.is_64, "{name}");
        assert_eq!(ours.kind, theirs.kind, "{name}");
        assert_eq!(ours.segments, theirs.segments, "{name}");
        assert_eq!(ours.dynamic, theirs.dynamic, "{name}");
        assert_eq!(ours.sections, theirs.sections, "{name}");
        assert_eq!(ours.dynamic_symbols, theirs.dynamic_symbols, "{name}");
        assert_eq!(ours.static_symbols, theirs.static_symbols, "{name}");
    }
    eprintln!("{} libraries agree", libraries.len());
}

#[test]
fn real_libraries_survive_mutation() {
    let Some((_, original)) = local_android_libraries(1).into_iter().next() else {
        return;
    };
    let length = original.len().min(8192);
    for position in 0..length {
        let mut mutated = original.clone();
        mutated[position] ^= 0xa5;
        let _ = Elf::parse(&mutated);
    }
    for cut in (0..original.len()).step_by(original.len() / 512 + 1) {
        let _ = Elf::parse(&original[..cut]);
    }
}

#[test]
#[ignore = "prints hardening of local libraries; run with --ignored --nocapture"]
fn print_local_hardening() {
    use msec::android::native::Hardening;
    for (name, bytes) in local_android_libraries(60) {
        let elf = Elf::parse(&bytes).unwrap();
        let hardening = Hardening::of(&elf);
        let short = name
            .rsplit('/')
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("/");
        eprintln!(
            "{short:70} nx={} pie={:?} canary={} relro={:?} fortify={} stripped={} debug={} textrel={} dart={} align={:?} rpath={:?} cc={:?}",
            hardening.nx,
            hardening.pie,
            hardening.stack_canary,
            hardening.relro,
            hardening.fortified.len(),
            hardening.stripped,
            hardening.debug_info,
            hardening.text_relocations,
            hardening.dart,
            hardening.load_alignment,
            hardening.rpath,
            hardening.compiler.as_deref().map(|c| &c[..c.len().min(40)])
        );
    }
}

/// Libraries written by `tests/fixtures/android/make_elf_fixtures.py` (Python, independent of
/// msec) parse the same with `object`. The section-less one only msec reads fully (its dynamic
/// symbols come from the GNU hash table, which `object` does not use without sections).
#[test]
fn fixture_libraries_parse_like_object() {
    for name in ["libhardened", "libweak", "libpartial", "libapp"] {
        let path = format!(
            "{}/tests/fixtures/android/native/{name}.so",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(msec_summary(&bytes), object_summary(&bytes), "{name}");
    }
}
