//! msec's Mach-O reader against Apple's tools on fixtures built with Xcode's toolchain
//! (tests/fixtures/macho, rebuilt by build_macho.sh): every load command as `otool -l` prints
//! it, imports and debug entries as `nm` lists them, the code signature as `codesign -dvvv`
//! describes and `codesign --verify` judges it, universal slices as `lipo -detailed_info`
//! lists them; then hostile files against llvm-objdump's verdicts.

use std::collections::BTreeMap;
use std::path::Path;

use msec::macho::signature::{
    CodeSignature, SLOT_DER_ENTITLEMENTS, SLOT_ENTITLEMENTS, SLOT_REQUIREMENTS, SignatureAnomaly,
};
use msec::macho::{
    Container, Hardening, MachO, MachOAnomalyKind, MachOError, command_name, full_version, parse,
    short_version,
};
use msec::plist;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/macho");

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(Path::new(FIXTURES).join(relative)).unwrap()
}

fn oracle(name: &str, kind: &str) -> String {
    String::from_utf8(read(&format!("oracle/{name}.{kind}.txt"))).unwrap()
}

fn binaries() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(Path::new(FIXTURES).join("bin"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// One load command as `otool -l` prints it.
#[derive(Debug, Default)]
struct OtoolCommand {
    fields: BTreeMap<String, String>,
    sections: Vec<BTreeMap<String, String>>,
}

/// `otool -l` output, one list of commands per architecture.
fn otool_commands(text: &str) -> Vec<Vec<OtoolCommand>> {
    let mut architectures: Vec<Vec<OtoolCommand>> = vec![Vec::new()];
    for line in text.lines() {
        if line.ends_with("):") && line.contains("(architecture ") {
            architectures.push(Vec::new());
            continue;
        }
        let commands = architectures.last_mut().unwrap();
        let trimmed = line.trim();
        if trimmed.starts_with("Load command ") {
            commands.push(OtoolCommand::default());
            continue;
        }
        let Some(command) = commands.last_mut() else {
            continue;
        };
        if trimmed == "Section" {
            command.sections.push(BTreeMap::new());
            continue;
        }
        let (key, value) = ["current version", "compatibility version", "time stamp"]
            .iter()
            .find_map(|key| {
                trimmed
                    .strip_prefix(key)
                    .map(|value| ((*key).to_owned(), value.trim().to_owned()))
            })
            .or_else(|| {
                trimmed
                    .split_once(char::is_whitespace)
                    .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
            })
            .unwrap_or_else(|| (trimmed.to_owned(), String::new()));
        match command.sections.last_mut() {
            Some(section) if key != "cmd" => {
                section.insert(key, value);
            }
            _ => {
                command.fields.insert(key, value);
            }
        }
    }
    architectures.retain(|commands| !commands.is_empty());
    architectures
}

/// `name (offset 24)` without the offset.
fn without_offset(value: &str) -> &str {
    value.split(" (offset ").next().unwrap()
}

/// Compares an image with `otool -l`'s reading of it, command by command.
fn compare_with_otool(name: &str, image: &MachO, commands: &[OtoolCommand]) {
    let names: Vec<String> = image
        .load_commands
        .iter()
        .map(|cmd| command_name(*cmd))
        .collect();
    let theirs: Vec<&str> = commands
        .iter()
        .map(|command| command.fields["cmd"].as_str())
        .collect();
    assert_eq!(names, theirs, "{name}: load commands");
    let mut segments = image.segments.iter();
    let mut dylibs = image.dylibs.iter();
    let mut rpaths = image.rpaths.iter();
    for command in commands {
        let field = |key: &str| command.fields[key].as_str();
        match field("cmd") {
            "LC_SEGMENT_64" => {
                let segment = segments.next().unwrap();
                assert_eq!(segment.name, field("segname"), "{name}");
                assert_eq!(segment.file_offset.to_string(), field("fileoff"), "{name}");
                assert_eq!(segment.file_size.to_string(), field("filesize"), "{name}");
                assert_eq!(
                    segment.sections.len().to_string(),
                    field("nsects"),
                    "{name}"
                );
                for (section, theirs) in segment.sections.iter().zip(&command.sections) {
                    assert_eq!(section.name, theirs["sectname"], "{name}");
                    assert_eq!(section.segment, theirs["segname"], "{name}");
                    assert_eq!(section.offset.to_string(), theirs["offset"], "{name}");
                    assert_eq!(format!("{:#018x}", section.size), theirs["size"], "{name}");
                }
            }
            "LC_LOAD_DYLIB" | "LC_LOAD_WEAK_DYLIB" | "LC_REEXPORT_DYLIB" => {
                let dylib = dylibs.next().unwrap();
                assert_eq!(dylib.name, without_offset(field("name")), "{name}");
                assert_eq!(
                    full_version(dylib.current_version),
                    field("current version")
                );
                assert_eq!(
                    full_version(dylib.compatibility_version),
                    field("compatibility version")
                );
            }
            "LC_ID_DYLIB" => {
                let id = image.id_dylib.as_ref().unwrap();
                assert_eq!(id.name, without_offset(field("name")), "{name}");
            }
            "LC_LOAD_DYLINKER" => {
                assert_eq!(
                    image.dylinker.as_deref(),
                    Some(without_offset(field("name")))
                );
            }
            "LC_RPATH" => {
                assert_eq!(
                    rpaths.next().unwrap(),
                    without_offset(field("path")),
                    "{name}"
                );
            }
            "LC_BUILD_VERSION" => {
                let build = image.build_version.as_ref().unwrap();
                assert_eq!(build.platform.to_string(), field("platform"), "{name}");
                assert_eq!(short_version(build.minimum_os), field("minos"), "{name}");
                assert_eq!(short_version(build.sdk), field("sdk"), "{name}");
            }
            "LC_ENCRYPTION_INFO_64" => {
                let encryption = image.encryption.unwrap();
                assert_eq!(encryption.offset.to_string(), field("cryptoff"), "{name}");
                assert_eq!(encryption.size.to_string(), field("cryptsize"), "{name}");
                assert_eq!(encryption.id.to_string(), field("cryptid"), "{name}");
            }
            "LC_CODE_SIGNATURE" | "LC_DYLD_CHAINED_FIXUPS" | "LC_DYLD_EXPORTS_TRIE" => {
                let linkedit = match field("cmd") {
                    "LC_CODE_SIGNATURE" => image.code_signature,
                    "LC_DYLD_CHAINED_FIXUPS" => image.chained_fixups,
                    _ => image.exports_trie,
                }
                .unwrap();
                assert_eq!(linkedit.offset.to_string(), field("dataoff"), "{name}");
                assert_eq!(linkedit.size.to_string(), field("datasize"), "{name}");
            }
            "LC_UUID" => {
                let uuid = image.uuid.unwrap();
                let hex: String = uuid.iter().map(|byte| format!("{byte:02X}")).collect();
                let formatted = format!(
                    "{}-{}-{}-{}-{}",
                    &hex[..8],
                    &hex[8..12],
                    &hex[12..16],
                    &hex[16..20],
                    &hex[20..]
                );
                assert_eq!(formatted, field("uuid"), "{name}");
            }
            "LC_MAIN" => {
                assert_eq!(image.entry_offset.unwrap().to_string(), field("entryoff"));
            }
            "LC_SYMTAB" => {
                let symbols = image.symbols.as_ref().unwrap();
                assert_eq!(symbols.count.to_string(), field("nsyms"), "{name}");
            }
            _ => {}
        }
    }
    assert!(segments.next().is_none() && dylibs.next().is_none() && rpaths.next().is_none());
}

/// The fields of `codesign -dvvv` output, its verify verdict and its entitlements XML.
struct Codesign {
    fields: BTreeMap<String, String>,
    verify: String,
    entitlements: Option<String>,
}

fn codesign(name: &str) -> Codesign {
    let text = oracle(name, "codesign");
    let (description, entitlements) = text.split_once("# entitlements").unwrap();
    let mut fields = BTreeMap::new();
    let mut verify = String::new();
    for line in description.lines() {
        if let Some(verdict) = line.strip_prefix("verify: ") {
            verify = verdict.to_owned();
        } else if let Some((key, value)) = line.split_once('=') {
            fields
                .entry(key.to_owned())
                .or_insert_with(|| value.to_owned());
        }
    }
    let entitlements = entitlements.trim();
    Codesign {
        fields,
        verify,
        entitlements: (!entitlements.is_empty()).then(|| entitlements.to_owned()),
    }
}

/// The signature checks `codesign --verify` makes on a lone binary: every page, and the
/// requirements and entitlements slots.
fn signature_valid(image_bytes: &[u8], signature: &CodeSignature) -> bool {
    let Some(directory) = signature.best_code_directory() else {
        return false;
    };
    let slots = [
        (SLOT_REQUIREMENTS, signature.requirements.as_deref()),
        (
            SLOT_ENTITLEMENTS,
            signature
                .entitlements
                .as_ref()
                .map(|entitlements| entitlements.blob.as_slice()),
        ),
        (SLOT_DER_ENTITLEMENTS, signature.der_entitlements.as_deref()),
    ];
    directory.verify_pages(image_bytes).valid()
        && slots.iter().all(|(slot, bytes)| match bytes {
            Some(bytes) => directory.verify_special(*slot, bytes) != Some(false),
            None => true,
        })
}

#[test]
fn images_read_as_otool_nm_and_codesign_read_them() {
    let names = binaries();
    assert!(names.len() >= 14, "{names:?}");
    for name in &names {
        let bytes = read(&format!("bin/{name}"));
        let file = parse(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
        let otool = otool_commands(&oracle(name, "otool"));
        assert_eq!(otool.len(), file.slices.len(), "{name}: architectures");
        for (slice, commands) in file.slices.iter().zip(&otool) {
            let image = slice.image.as_ref().unwrap();
            assert_eq!(image.anomalies, [], "{name}");
            compare_with_otool(name, image, commands);
        }
        if file.container != Container::Thin {
            continue;
        }
        let image = file.slices[0].image.as_ref().unwrap();

        // nm: imports and debug entries.
        let nm = oracle(name, "nm");
        let (imports, debug) = nm
            .strip_prefix("# nm -u\n")
            .unwrap()
            .split_once("# debug entries (nm -ap, type -, except OPT)\n")
            .unwrap();
        let imports: Vec<&str> = imports.lines().collect();
        let symbols = image.symbols.as_ref().unwrap();
        assert_eq!(symbols.imports, imports, "{name}: imports");
        assert_eq!(
            symbols.debug.to_string(),
            debug.trim(),
            "{name}: debug entries"
        );

        // codesign: what the signature says, and whether it verifies.
        let theirs = codesign(name);
        match &image.signature {
            None => assert_eq!(theirs.verify, "code object is not signed at all", "{name}"),
            Some(Err(error)) => panic!("{name}: {error}"),
            Some(Ok(signature)) => {
                let directory = signature.best_code_directory().unwrap();
                assert_eq!(theirs.fields["Identifier"], directory.identifier, "{name}");
                let summary = format!(
                    "v={:x} size={} flags={:#x}",
                    directory.version,
                    directory.size(),
                    directory.flags
                );
                assert!(
                    theirs.fields["CodeDirectory v"].starts_with(&summary["v=".len()..]),
                    "{name}: {summary} vs {}",
                    theirs.fields["CodeDirectory v"]
                );
                assert!(theirs.fields["CodeDirectory v"].contains(&format!(
                    "hashes={}+{}",
                    directory.code_slots, directory.special_slots
                )));
                assert_eq!(
                    Some(theirs.fields["CDHash"].clone()),
                    directory.cdhash(),
                    "{name}"
                );
                assert_eq!(
                    theirs.fields["TeamIdentifier"],
                    directory
                        .team_id
                        .clone()
                        .unwrap_or_else(|| "not set".to_owned()),
                    "{name}"
                );
                assert_eq!(
                    signature_valid(&bytes, signature),
                    theirs.verify == "valid",
                    "{name}: codesign says {}",
                    theirs.verify
                );
                let ours = signature.entitlements.as_ref().map(|entitlements| {
                    plist::to_xml(&entitlements.plist.as_ref().unwrap().root).unwrap()
                });
                let apple = theirs
                    .entitlements
                    .as_ref()
                    .map(|xml| plist::to_xml(&plist::parse(xml.as_bytes()).unwrap().root).unwrap());
                assert_eq!(ours, apple, "{name}: entitlements");
            }
        }
    }
}

/// The universal file's slices are the thin files lipo was given, at the offsets it lists.
#[test]
fn universal_slices_match_lipo() {
    let universal = parse(&read("bin/universal")).unwrap();
    assert_eq!(universal.container, Container::Fat { wide: false });
    let lipo = oracle("universal", "lipo");
    let offsets: Vec<String> = lipo
        .lines()
        .filter_map(|line| line.trim().strip_prefix("offset "))
        .map(str::to_owned)
        .collect();
    let sizes: Vec<String> = lipo
        .lines()
        .filter_map(|line| line.trim().strip_prefix("size "))
        .map(str::to_owned)
        .collect();
    let architectures: Vec<String> = universal
        .slices
        .iter()
        .map(|slice| slice.architecture())
        .collect();
    assert_eq!(architectures, ["arm64", "arm64e"]);
    for (index, slice) in universal.slices.iter().enumerate() {
        assert_eq!(slice.offset.to_string(), offsets[index]);
        assert_eq!(slice.size.to_string(), sizes[index]);
    }
    for (slice, thin) in universal.slices.iter().zip(["hardened", "hardened-arm64e"]) {
        let alone = parse(&read(&format!("bin/{thin}"))).unwrap();
        assert_eq!(slice.image, alone.slices[0].image, "{thin}");
    }
    assert_eq!(universal.anomalies, []);
}

/// MobSF's checksec, per fixture: PIE, stack execution, stack protector, ARC, encryption,
/// signature, rpaths, stripping.
#[test]
fn hardening_follows_the_build() {
    type Row = (
        Option<bool>,
        bool,
        bool,
        bool,
        Option<bool>,
        bool,
        usize,
        bool,
    );
    let expected: BTreeMap<&str, Row> = BTreeMap::from([
        // (pie, nx_stack, canary, arc, encrypted, signature, rpaths, stripped)
        (
            "hardened",
            (Some(true), true, true, true, Some(false), true, 0, true),
        ),
        (
            "encrypted",
            (Some(true), true, true, true, Some(true), true, 0, true),
        ),
        (
            "tampered",
            (Some(true), true, true, true, Some(false), true, 0, true),
        ),
        (
            "unsigned",
            (Some(true), true, true, true, Some(false), false, 0, true),
        ),
        (
            "plain",
            (Some(true), true, true, false, Some(false), false, 0, true),
        ),
        (
            "no-canary",
            (Some(true), true, false, false, Some(false), true, 0, true),
        ),
        (
            "stack-exec",
            (Some(true), false, true, false, Some(false), true, 0, true),
        ),
        (
            "no-pie",
            (Some(false), true, true, false, Some(false), true, 0, true),
        ),
        (
            "manual",
            (Some(true), true, false, false, Some(false), true, 0, true),
        ),
        (
            "debug",
            (Some(true), true, true, false, Some(false), true, 0, false),
        ),
        // iOS libraries carry LC_ENCRYPTION_INFO_64 too (cryptid 0 until the App Store sets it).
        (
            "library",
            (None, true, false, false, Some(false), true, 1, true),
        ),
    ]);
    for (name, row) in expected {
        let file = parse(&read(&format!("bin/{name}"))).unwrap();
        let image = file.slices[0].image.as_ref().unwrap();
        let hardening = Hardening::of(image);
        let ours: Row = (
            hardening.pie,
            hardening.nx_stack,
            hardening.stack_canary,
            hardening.arc,
            hardening.encrypted,
            hardening.code_signature,
            hardening.rpaths,
            hardening.stripped,
        );
        assert_eq!(ours, row, "{name}");
    }
    let swift = parse(&read("bin/swift")).unwrap();
    let swift = Hardening::of(swift.slices[0].image.as_ref().unwrap());
    assert!(swift.swift && swift.arc, "{swift:?}");
}

/// Each hostile file: what msec reports, and agreement with llvm-objdump (LLVM's strict reader)
/// that the structures it refuses are malformed.
#[test]
fn hostile_files_are_reported() {
    let verdicts: BTreeMap<String, String> = String::from_utf8(read("oracle/hostile.txt"))
        .unwrap()
        .lines()
        .map(|line| {
            let (name, verdict) = line.split_once(": ").unwrap();
            (name.to_owned(), verdict.to_owned())
        })
        .collect();
    let expect_error = |name: &str, error: MachOError| {
        assert_eq!(
            parse(&read(&format!("hostile/{name}"))),
            Err(error),
            "{name}"
        );
    };
    expect_error("truncated-header", MachOError::Truncated);
    expect_error("big-endian", MachOError::BigEndian);
    expect_error("universal-java-like", MachOError::NotMachO);
    expect_error("commands-past-end", MachOError::LoadCommandsOutOfBounds);
    let image_of = |name: &str| -> MachO {
        let file = parse(&read(&format!("hostile/{name}"))).unwrap();
        file.slices[0].image.clone().unwrap()
    };
    let has = |name: &str, kind: MachOAnomalyKind| {
        let image = image_of(name);
        assert!(
            image.anomalies.iter().any(|anomaly| anomaly.kind == kind),
            "{name}: {:?}",
            image.anomalies
        );
    };
    has(
        "too-many-commands",
        MachOAnomalyKind::LoadCommandCountMismatch,
    );
    has(
        "command-size-zero",
        MachOAnomalyKind::InvalidLoadCommandSize {
            command: 0x1b,
            size: 0,
        },
    );
    has(
        "command-size-unaligned",
        MachOAnomalyKind::InvalidLoadCommandSize {
            command: 0x1b,
            size: 28,
        },
    );
    has(
        "dylib-name-outside",
        MachOAnomalyKind::InvalidCommandString { command: 0xc },
    );
    has(
        "rpath-unterminated",
        MachOAnomalyKind::InvalidCommandString {
            command: 0x8000_001c,
        },
    );
    has(
        "segment-outside",
        MachOAnomalyKind::RangeOutOfBounds {
            name: "__LINKEDIT".into(),
        },
    );
    has("symbols-outside", MachOAnomalyKind::SymbolTableOutOfBounds);
    has(
        "symbol-name-outside",
        MachOAnomalyKind::SymbolNameOutOfBounds,
    );
    has(
        "signature-outside",
        MachOAnomalyKind::LinkeditDataOutOfBounds { command: 0x1d },
    );
    has(
        "duplicate-exports-trie",
        MachOAnomalyKind::DuplicateCommand {
            command: 0x8000_0033,
        },
    );
    let signature_of = |name: &str| image_of(name).signature.unwrap();
    assert_eq!(
        signature_of("signature-not-superblob"),
        Err(msec::macho::signature::SignatureError::NotSuperBlob)
    );
    let huge = signature_of("signature-count-huge").unwrap();
    assert!(huge.anomalies.contains(&SignatureAnomaly::TooManyBlobs));
    for name in ["code-directory-hashes-outside", "code-directory-slots-huge"] {
        let signature = signature_of(name).unwrap();
        assert!(signature.best_code_directory().is_none(), "{name}");
        assert!(
            matches!(
                signature.anomalies.as_slice(),
                [SignatureAnomaly::InvalidCodeDirectory { slot: 0, .. }]
            ),
            "{name}: {:?}",
            signature.anomalies
        );
    }
    let universal = |name: &str| parse(&read(&format!("hostile/{name}"))).unwrap();
    assert!(
        universal("universal-overlapping")
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == MachOAnomalyKind::OverlappingSlices)
    );
    assert!(
        universal("universal-slice-outside").slices[0]
            .image
            .is_err()
    );
    assert!(
        universal("universal-nested")
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == MachOAnomalyKind::NestedUniversal)
    );

    // Whatever llvm-objdump refuses, msec reports as malformed (an error, or an anomaly at
    // the file or image level).
    for (name, verdict) in &verdicts {
        if !verdict.starts_with("llvm-objdump refuses") {
            continue;
        }
        let reported = match parse(&read(&format!("hostile/{name}"))) {
            Err(_) => true,
            Ok(file) => {
                !file.anomalies.is_empty()
                    || file.slices.iter().any(|slice| match &slice.image {
                        Err(_) => true,
                        Ok(image) => !image.anomalies.is_empty(),
                    })
            }
        };
        assert!(
            reported,
            "{name}: llvm-objdump {verdict}, msec reports nothing"
        );
    }
}

/// Every single-byte change to the hardened image and every truncation is read or refused
/// without panicking, and signature verification never panics either.
#[test]
fn edited_images_never_panic() {
    let original = read("bin/hardened");
    for position in (0..original.len()).step_by(11) {
        for value in [0x00, 0xff, original[position] ^ 0x80] {
            let mut edited = original.clone();
            edited[position] = value;
            exercise(&edited);
        }
        if position % 11 == 0 && position % 7 == 0 {
            exercise(&original[..position]);
        }
    }
}

fn exercise(bytes: &[u8]) {
    if let Ok(file) = parse(bytes) {
        for slice in &file.slices {
            if let Ok(image) = &slice.image {
                let _ = Hardening::of(image);
                if let Some(Ok(signature)) = &image.signature {
                    for directory in &signature.code_directories {
                        let _ = directory.verify_pages(bytes);
                        let _ = directory.cdhash();
                    }
                }
            }
        }
    }
}
