//! Archive reader tests. Hostile archives are crafted byte by byte with [`ArchiveBuilder`];
//! valid ones are also produced by the independent `zip` crate as a cross-check.

use std::io::{Cursor, Write};

use flate2::Compression;
use flate2::write::DeflateEncoder;
use msec::archive::{AnomalyKind, ArchiveError, Limits, LocalHeaderField, NameIssue, ZipArchive};

// ---------------------------------------------------------------------------------------------
// Crafting archives
// ---------------------------------------------------------------------------------------------

/// One entry to write. Defaults produce a well-formed deflated file.
#[derive(Clone)]
struct EntrySpec {
    name: Vec<u8>,
    content: Vec<u8>,
    deflate: bool,
    flags: u16,
    unix_mode: Option<u32>,
    method_override: Option<u16>,
    crc_override: Option<u32>,
    declared_size_override: Option<u32>,
    /// Name written in the local header instead of `name`.
    local_name: Option<Vec<u8>>,
    /// Write no local header; point the central directory record at this earlier entry's.
    reuse_local_header_of: Option<usize>,
    data_descriptor: bool,
}

impl EntrySpec {
    fn new(name: impl AsRef<[u8]>, content: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            content: content.as_ref().to_vec(),
            deflate: true,
            flags: 0,
            unix_mode: None,
            method_override: None,
            crc_override: None,
            declared_size_override: None,
            local_name: None,
            reuse_local_header_of: None,
            data_descriptor: false,
        }
    }

    fn stored(mut self) -> Self {
        self.deflate = false;
        self
    }

    fn method(&self) -> u16 {
        self.method_override
            .unwrap_or(if self.deflate { 8 } else { 0 })
    }

    fn flags(&self) -> u16 {
        self.flags | if self.data_descriptor { 0x0008 } else { 0 }
    }

    fn stored_data(&self) -> Vec<u8> {
        if !self.deflate {
            return self.content.clone();
        }
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&self.content).unwrap();
        encoder.finish().unwrap()
    }

    fn crc32(&self) -> u32 {
        self.crc_override
            .unwrap_or_else(|| crc32fast::hash(&self.content))
    }

    fn declared_size(&self) -> u32 {
        self.declared_size_override
            .unwrap_or(self.content.len() as u32)
    }
}

#[derive(Default)]
struct ArchiveBuilder {
    entries: Vec<EntrySpec>,
    prefix: Vec<u8>,
    /// Prefix added without adjusting offsets (`cat stub app.apk`).
    unadjusted_prefix: bool,
    signing_block_payload: Option<Vec<u8>>,
    gap_before_central_directory: Vec<u8>,
    zip64: bool,
    comment: Vec<u8>,
    trailing: Vec<u8>,
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

impl ArchiveBuilder {
    fn with(entries: Vec<EntrySpec>) -> Self {
        Self {
            entries,
            ..Self::default()
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut out = self.prefix.clone();
        let base = if self.unadjusted_prefix {
            self.prefix.len() as u64
        } else {
            0
        };
        let mut central_directory = Vec::new();
        let mut local_offsets = Vec::new();
        for spec in &self.entries {
            let stored = spec.stored_data();
            let offset = match spec.reuse_local_header_of {
                Some(index) => local_offsets[index],
                None => {
                    let offset = out.len() as u64 - base;
                    self.write_local_entry(&mut out, spec, &stored);
                    offset
                }
            };
            local_offsets.push(offset);
            self.write_central_record(&mut central_directory, spec, stored.len() as u32, offset);
        }
        if let Some(payload) = &self.signing_block_payload {
            let size = (payload.len() + 8 + 16) as u64;
            put64(&mut out, size);
            out.extend_from_slice(payload);
            put64(&mut out, size);
            out.extend_from_slice(b"APK Sig Block 42");
        }
        out.extend_from_slice(&self.gap_before_central_directory);
        let central_directory_offset = out.len() as u64 - base;
        out.extend_from_slice(&central_directory);
        self.write_end_records(
            &mut out,
            base,
            central_directory_offset,
            central_directory.len() as u64,
        );
        out.extend_from_slice(&self.trailing);
        out
    }

    fn write_local_entry(&self, out: &mut Vec<u8>, spec: &EntrySpec, stored: &[u8]) {
        let name = spec.local_name.as_ref().unwrap_or(&spec.name);
        put32(out, 0x0403_4b50);
        put16(out, 20);
        put16(out, spec.flags());
        put16(out, spec.method());
        put32(out, 0); // time and date
        let (crc, compressed, uncompressed) = if spec.data_descriptor {
            (0, 0, 0)
        } else if self.zip64 {
            (spec.crc32(), u32::MAX, u32::MAX)
        } else {
            (spec.crc32(), stored.len() as u32, spec.declared_size())
        };
        put32(out, crc);
        put32(out, compressed);
        put32(out, uncompressed);
        put16(out, name.len() as u16);
        put16(out, if self.zip64 { 20 } else { 0 });
        out.extend_from_slice(name);
        if self.zip64 {
            put16(out, 0x0001);
            put16(out, 16);
            put64(out, u64::from(spec.declared_size()));
            put64(out, stored.len() as u64);
        }
        out.extend_from_slice(stored);
        if spec.data_descriptor {
            put32(out, 0x0807_4b50);
            put32(out, spec.crc32());
            put32(out, stored.len() as u32);
            put32(out, spec.declared_size());
        }
    }

    fn write_central_record(
        &self,
        out: &mut Vec<u8>,
        spec: &EntrySpec,
        compressed: u32,
        offset: u64,
    ) {
        put32(out, 0x0201_4b50);
        put16(
            out,
            if spec.unix_mode.is_some() {
                (3 << 8) | 20
            } else {
                20
            },
        );
        put16(out, 20);
        put16(out, spec.flags());
        put16(out, spec.method());
        put32(out, 0);
        put32(out, spec.crc32());
        if self.zip64 {
            put32(out, u32::MAX);
            put32(out, u32::MAX);
        } else {
            put32(out, compressed);
            put32(out, spec.declared_size());
        }
        put16(out, spec.name.len() as u16);
        put16(out, if self.zip64 { 28 } else { 0 });
        put16(out, 0); // comment
        put16(out, 0); // disk
        put16(out, 0); // internal attributes
        put32(out, spec.unix_mode.map_or(0, |mode| mode << 16));
        put32(out, if self.zip64 { u32::MAX } else { offset as u32 });
        out.extend_from_slice(&spec.name);
        if self.zip64 {
            put16(out, 0x0001);
            put16(out, 24);
            put64(out, u64::from(spec.declared_size()));
            put64(out, u64::from(compressed));
            put64(out, offset);
        }
    }

    fn write_end_records(
        &self,
        out: &mut Vec<u8>,
        base: u64,
        directory_offset: u64,
        directory_size: u64,
    ) {
        let entries = self.entries.len() as u64;
        if self.zip64 {
            let zip64_offset = out.len() as u64 - base;
            put32(out, 0x0606_4b50);
            put64(out, 44);
            put16(out, 45);
            put16(out, 45);
            put32(out, 0);
            put32(out, 0);
            put64(out, entries);
            put64(out, entries);
            put64(out, directory_size);
            put64(out, directory_offset);
            put32(out, 0x0706_4b50);
            put32(out, 0);
            put64(out, zip64_offset);
            put32(out, 1);
        }
        put32(out, 0x0605_4b50);
        put32(out, 0); // disk numbers
        let (count, size, offset) = if self.zip64 {
            (u16::MAX, u32::MAX, u32::MAX)
        } else {
            (
                entries as u16,
                directory_size as u32,
                directory_offset as u32,
            )
        };
        put16(out, count);
        put16(out, count);
        put32(out, size);
        put32(out, offset);
        put16(out, self.comment.len() as u16);
        out.extend_from_slice(&self.comment);
    }
}

fn open(bytes: Vec<u8>) -> ZipArchive<Cursor<Vec<u8>>> {
    open_with(bytes, Limits::default()).expect("archive should open")
}

fn open_with(bytes: Vec<u8>, limits: Limits) -> Result<ZipArchive<Cursor<Vec<u8>>>, ArchiveError> {
    ZipArchive::open(Cursor::new(bytes), limits)
}

fn kinds(archive: &ZipArchive<Cursor<Vec<u8>>>) -> Vec<AnomalyKind> {
    archive
        .anomalies()
        .iter()
        .map(|anomaly| anomaly.kind.clone())
        .collect()
}

fn read_named(archive: &mut ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
    archive
        .read_by_name(name)
        .unwrap()
        .expect("entry should exist")
}

fn standard_entries() -> Vec<EntrySpec> {
    vec![
        EntrySpec::new("AndroidManifest.xml", b"<manifest/>".repeat(20)),
        EntrySpec::new("classes.dex", b"dex\n035\0 payload").stored(),
        EntrySpec::new("res/", b"").stored(),
    ]
}

// ---------------------------------------------------------------------------------------------
// Well-formed archives
// ---------------------------------------------------------------------------------------------

#[test]
fn reads_stored_and_deflated_entries_without_anomalies() {
    let mut archive = open(ArchiveBuilder::with(standard_entries()).build());
    assert!(archive.anomalies().is_empty(), "{:?}", archive.anomalies());
    assert_eq!(archive.entries().len(), 3);
    assert_eq!(
        read_named(&mut archive, "AndroidManifest.xml"),
        b"<manifest/>".repeat(20)
    );
    assert_eq!(
        read_named(&mut archive, "classes.dex"),
        b"dex\n035\0 payload"
    );
    assert!(archive.find("res/").unwrap().is_directory);
    assert!(archive.read_by_name("missing").unwrap().is_none());
    assert!(archive.anomalies().is_empty());
}

#[test]
fn agrees_with_an_independent_writer() {
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    let files: [(&str, &[u8], CompressionMethod); 3] = [
        (
            "AndroidManifest.xml",
            b"<manifest package=\"a.b\"/>",
            CompressionMethod::Deflated,
        ),
        (
            "lib/arm64-v8a/libx.so",
            b"\x7fELF....",
            CompressionMethod::Stored,
        ),
        (
            "assets/big.txt",
            &[b'z'; 100_000],
            CompressionMethod::Deflated,
        ),
    ];
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content, method) in files {
        writer
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(content).unwrap();
    }
    writer
        .add_directory("res/", SimpleFileOptions::default())
        .unwrap();
    let bytes = writer.finish().unwrap().into_inner();

    let mut archive = open(bytes);
    assert!(archive.anomalies().is_empty(), "{:?}", archive.anomalies());
    for (name, content, _) in files {
        assert_eq!(read_named(&mut archive, name), content, "{name}");
    }
    assert!(archive.find("res/").unwrap().is_directory);
}

#[test]
fn data_descriptors_are_accounted_for() {
    let mut entries = standard_entries();
    for entry in &mut entries {
        entry.data_descriptor = true;
    }
    let mut archive = open(ArchiveBuilder::with(entries).build());
    assert!(archive.anomalies().is_empty(), "{:?}", archive.anomalies());
    assert_eq!(
        read_named(&mut archive, "classes.dex"),
        b"dex\n035\0 payload"
    );
}

#[test]
fn reads_zip64_archives() {
    let mut builder = ArchiveBuilder::with(standard_entries());
    builder.zip64 = true;
    let mut archive = open(builder.build());
    assert!(archive.layout().zip64);
    assert!(archive.anomalies().is_empty(), "{:?}", archive.anomalies());
    assert_eq!(
        read_named(&mut archive, "AndroidManifest.xml"),
        b"<manifest/>".repeat(20)
    );
}

#[test]
fn finds_the_apk_signing_block_without_calling_it_hidden_data() {
    let mut builder = ArchiveBuilder::with(standard_entries());
    builder.signing_block_payload = Some(vec![0xAB; 40]);
    let archive = open(builder.build());
    let layout = archive.layout();
    let block = layout.apk_signing_block.clone().expect("signing block");
    assert_eq!(block.end, layout.central_directory_offset);
    assert_eq!(block.end - block.start, 40 + 8 + 8 + 16);
    assert!(archive.anomalies().is_empty(), "{:?}", archive.anomalies());
}

// ---------------------------------------------------------------------------------------------
// Not archives, truncation, limits
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_files_that_are_not_archives() {
    for bytes in [Vec::new(), b"not a zip".to_vec(), vec![0; 4096]] {
        assert!(matches!(
            open_with(bytes, Limits::default()),
            Err(ArchiveError::NotAnArchive)
        ));
    }
}

#[test]
fn truncation_at_every_length_never_panics() {
    let bytes = ArchiveBuilder::with(standard_entries()).build();
    for length in 0..bytes.len() {
        if let Ok(mut archive) = open_with(bytes[..length].to_vec(), Limits::default()) {
            for index in 0..archive.entries().len() {
                let _ = archive.read(index);
            }
        }
    }
}

#[test]
fn enforces_archive_and_directory_limits() {
    let bytes = ArchiveBuilder::with(standard_entries()).build();
    let small_archive = Limits {
        max_archive_bytes: 10,
        ..Limits::default()
    };
    assert!(matches!(
        open_with(bytes.clone(), small_archive),
        Err(ArchiveError::ArchiveTooLarge { .. })
    ));
    let few_entries = Limits {
        max_entries: 2,
        ..Limits::default()
    };
    assert!(matches!(
        open_with(bytes.clone(), few_entries),
        Err(ArchiveError::TooManyEntries {
            entries: 3,
            limit: 2
        })
    ));
    let small_directory = Limits {
        max_central_directory_bytes: 50,
        ..Limits::default()
    };
    assert!(matches!(
        open_with(bytes, small_directory),
        Err(ArchiveError::CentralDirectoryTooLarge { .. })
    ));
}

#[test]
fn enforces_entry_limit() {
    let bytes = ArchiveBuilder::with(vec![EntrySpec::new("a", [7; 100]).stored()]).build();
    let limits = Limits {
        max_entry_bytes: 99,
        ..Limits::default()
    };
    let mut archive = open_with(bytes, limits).unwrap();
    assert!(matches!(
        archive.read(0),
        Err(ArchiveError::EntryTooLarge { limit: 99, .. })
    ));
}

#[test]
fn stops_decompression_bombs_at_the_ratio_limit() {
    let bytes =
        ArchiveBuilder::with(vec![EntrySpec::new("bomb", vec![0; 8 * 1024 * 1024])]).build();
    let limits = Limits {
        max_compression_ratio: 100,
        ratio_check_after_bytes: 4096,
        ..Limits::default()
    };
    let mut archive = open_with(bytes, limits).unwrap();
    assert!(matches!(
        archive.read(0),
        Err(ArchiveError::CompressionRatioExceeded { limit: 100, .. })
    ));
}

#[test]
fn enforces_total_budget_across_reads() {
    let entries = vec![
        EntrySpec::new("a", [1; 100]).stored(),
        EntrySpec::new("b", [2; 100]).stored(),
    ];
    let limits = Limits {
        max_total_bytes: 150,
        ..Limits::default()
    };
    let mut archive = open_with(ArchiveBuilder::with(entries).build(), limits).unwrap();
    assert_eq!(archive.read(0).unwrap(), [1; 100]);
    assert!(matches!(
        archive.read(1),
        Err(ArchiveError::TotalBudgetExceeded { limit: 150 })
    ));
}

#[test]
fn reports_missing_entries_by_index() {
    let mut archive = open(ArchiveBuilder::with(standard_entries()).build());
    assert!(matches!(
        archive.read(99),
        Err(ArchiveError::NoSuchEntry { index: 99 })
    ));
}

// ---------------------------------------------------------------------------------------------
// Anomalies
// ---------------------------------------------------------------------------------------------

#[test]
fn duplicate_names_are_flagged_and_the_first_entry_wins() {
    let entries = vec![
        EntrySpec::new("classes.dex", b"first"),
        EntrySpec::new("classes.dex", b"second"),
    ];
    let mut archive = open(ArchiveBuilder::with(entries).build());
    let anomaly = archive
        .anomalies()
        .iter()
        .find(|anomaly| anomaly.kind == AnomalyKind::DuplicateName)
        .expect("duplicate flagged");
    assert!(anomaly.kind.rejected_by_android());
    assert_eq!(anomaly.entry.as_deref(), Some("classes.dex"));
    assert_eq!(read_named(&mut archive, "classes.dex"), b"first");
}

#[test]
fn janus_style_prefix_is_flagged_and_entries_still_read() {
    let mut builder = ArchiveBuilder::with(standard_entries());
    builder.prefix = b"dex\n035\0".repeat(8);
    let mut archive = open(builder.build());
    assert_eq!(archive.layout().shift, 0);
    assert!(kinds(&archive).contains(&AnomalyKind::DataBeforeFirstEntry { bytes: 64 }));
    assert_eq!(
        read_named(&mut archive, "classes.dex"),
        b"dex\n035\0 payload"
    );
}

#[test]
fn prefix_without_adjusted_offsets_is_recovered() {
    let mut builder = ArchiveBuilder::with(standard_entries());
    builder.prefix = vec![0x90; 100];
    builder.unadjusted_prefix = true;
    let mut archive = open(builder.build());
    assert_eq!(archive.layout().shift, 100);
    assert!(kinds(&archive).contains(&AnomalyKind::DataBeforeFirstEntry { bytes: 100 }));
    assert_eq!(
        read_named(&mut archive, "classes.dex"),
        b"dex\n035\0 payload"
    );
}

#[test]
fn fake_encryption_flag_is_flagged_but_data_still_reads() {
    let mut entry = EntrySpec::new("classes.dex", b"plain dex");
    entry.flags = 0x0001;
    let mut archive = open(ArchiveBuilder::with(vec![entry]).build());
    let anomaly = &archive.anomalies()[0];
    assert_eq!(anomaly.kind, AnomalyKind::EncryptionFlagSet);
    assert!(!anomaly.kind.rejected_by_android());
    assert_eq!(archive.read(0).unwrap(), b"plain dex");
}

#[test]
fn hostile_names_are_flagged_and_never_used_as_paths() {
    let entries = vec![
        EntrySpec::new("../../../etc/evil", b"x"),
        EntrySpec::new("/abs/path", b"x"),
        EntrySpec::new("dir\\file", b"x"),
    ];
    let mut archive = open(ArchiveBuilder::with(entries).build());
    let found = kinds(&archive);
    for issue in [
        NameIssue::ParentTraversal,
        NameIssue::AbsolutePath,
        NameIssue::Backslash,
    ] {
        assert!(
            found.contains(&AnomalyKind::SuspiciousName(issue)),
            "{issue:?}"
        );
    }
    assert_eq!(read_named(&mut archive, "../../../etc/evil"), b"x");
}

#[test]
fn symlinks_are_flagged() {
    let mut entry = EntrySpec::new("lib/link.so", b"/system/lib/libc.so").stored();
    entry.unix_mode = Some(0o120_777);
    let archive = open(ArchiveBuilder::with(vec![entry]).build());
    assert!(archive.entries()[0].is_symlink);
    assert_eq!(kinds(&archive), vec![AnomalyKind::Symlink]);
}

#[test]
fn invalid_name_encoding_is_flagged() {
    let archive = open(ArchiveBuilder::with(vec![EntrySpec::new(b"bad\xffname", b"x")]).build());
    assert_eq!(kinds(&archive), vec![AnomalyKind::InvalidNameEncoding]);
    assert_eq!(archive.entries()[0].name, "bad\u{fffd}name");
    assert_eq!(archive.entries()[0].raw_name, b"bad\xffname");
}

#[test]
fn local_header_name_mismatch_is_flagged_but_readable() {
    let mut entry = EntrySpec::new("AndroidManifest.xml", b"<manifest/>");
    entry.local_name = Some(b"AndroidManifest.xmL".to_vec());
    let mut archive = open(ArchiveBuilder::with(vec![entry]).build());
    let expected = AnomalyKind::LocalHeaderMismatch {
        field: LocalHeaderField::Name,
    };
    assert_eq!(kinds(&archive), vec![expected.clone()]);
    assert!(expected.rejected_by_android());
    assert_eq!(archive.read(0).unwrap(), b"<manifest/>");
}

#[test]
fn shared_local_headers_are_flagged_as_overlapping() {
    let content = b"shared data".repeat(10);
    let mut second = EntrySpec::new("b.txt", &content);
    second.reuse_local_header_of = Some(0);
    let archive =
        open(ArchiveBuilder::with(vec![EntrySpec::new("a.txt", &content), second]).build());
    let found = kinds(&archive);
    assert!(
        found.contains(&AnomalyKind::OverlappingData {
            other: "a.txt".into()
        }),
        "{found:?}"
    );
    assert!(found.contains(&AnomalyKind::LocalHeaderMismatch {
        field: LocalHeaderField::Name
    }));
}

#[test]
fn unsupported_compression_is_flagged_and_refused() {
    let mut entry = EntrySpec::new("classes.dex", b"bzip2 pretender").stored();
    entry.method_override = Some(12);
    let mut archive = open(ArchiveBuilder::with(vec![entry]).build());
    assert_eq!(
        kinds(&archive),
        vec![AnomalyKind::UnsupportedCompression { method: 12 }]
    );
    assert!(matches!(
        archive.read(0),
        Err(ArchiveError::UnsupportedCompression { method: 12, .. })
    ));
}

#[test]
fn crc_and_size_mismatches_are_recorded_once_on_read() {
    let mut bad_crc = EntrySpec::new("a", b"content");
    bad_crc.crc_override = Some(0xDEAD_BEEF);
    let mut bad_size = EntrySpec::new("b", b"content").stored();
    bad_size.declared_size_override = Some(3);
    let mut archive = open(ArchiveBuilder::with(vec![bad_crc, bad_size]).build());
    assert!(
        archive.anomalies().is_empty(),
        "found before reading: {:?}",
        archive.anomalies()
    );
    for _ in 0..2 {
        assert_eq!(archive.read(0).unwrap(), b"content");
        assert_eq!(archive.read(1).unwrap(), b"content");
    }
    assert_eq!(
        kinds(&archive),
        vec![
            AnomalyKind::CrcMismatch,
            AnomalyKind::DeclaredSizeMismatch {
                declared: 3,
                actual: 7
            }
        ]
    );
}

#[test]
fn hidden_data_before_the_central_directory_is_flagged() {
    let mut builder = ArchiveBuilder::with(standard_entries());
    builder.gap_before_central_directory = b"smuggled payload".to_vec();
    let archive = open(builder.build());
    assert!(
        matches!(
            kinds(&archive)[..],
            [AnomalyKind::HiddenData { bytes: 16, .. }]
        ),
        "{:?}",
        kinds(&archive)
    );
}

#[test]
fn end_record_hidden_in_the_comment_is_flagged() {
    let plain = ArchiveBuilder::with(standard_entries()).build();
    // A copy of the real end record with no comment, placed as the comment: Android picks it.
    let mut fake_end_record = plain[plain.len() - 22..].to_vec();
    fake_end_record[20..22].copy_from_slice(&0u16.to_le_bytes());
    let mut builder = ArchiveBuilder::with(standard_entries());
    builder.comment = fake_end_record;
    let archive = open(builder.build());
    assert!(
        kinds(&archive).contains(&AnomalyKind::MultipleEndRecords),
        "{:?}",
        kinds(&archive)
    );
}

#[test]
fn trailing_bytes_after_the_end_record_are_flagged() {
    let mut builder = ArchiveBuilder::with(standard_entries());
    builder.trailing = vec![0; 10];
    let archive = open(builder.build());
    let found = kinds(&archive);
    assert_eq!(found, vec![AnomalyKind::CommentLengthMismatch]);
    assert!(found[0].rejected_by_android());
}

// ---------------------------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------------------------

/// Every single-byte mutation of a small valid archive must open or fail cleanly, and every
/// entry of an opened one must read or fail cleanly. A panic fails the test.
#[test]
fn single_byte_mutations_never_panic() {
    let mut entries = standard_entries();
    entries[0].content = b"<manifest/>".to_vec();
    let mut builder = ArchiveBuilder::with(entries);
    builder.signing_block_payload = Some(vec![1; 8]);
    let original = builder.build();
    let limits = Limits {
        max_entry_bytes: 1 << 20,
        max_total_bytes: 1 << 22,
        ..Limits::default()
    };
    for position in 0..original.len() {
        for replacement in [
            0x00,
            0xFF,
            original[position] ^ 0x01,
            original[position] ^ 0x80,
        ] {
            let mut mutated = original.clone();
            mutated[position] = replacement;
            if let Ok(mut archive) = open_with(mutated, limits) {
                for index in 0..archive.entries().len() {
                    let _ = archive.read(index);
                }
            }
        }
    }
}
