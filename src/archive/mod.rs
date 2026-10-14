//! Safe reader for ZIP-based packages (APK, AAB, XAPK, APKS, JAR, AAR, IPA).
//!
//! Packages are hostile input. This reader:
//!
//! - never extracts to disk: entries are looked up by name and decompressed into memory, so
//!   names such as `../../x` cannot write anywhere;
//! - enforces [`Limits`] on archive size, entry count, central directory size, per-entry and
//!   total output, and compression ratio, using actual output rather than declared sizes;
//! - follows Android's own ZIP rules (AOSP `libziparchive`): the end record closest to the end
//!   of the file, stored and deflate only, the encryption flag ignored, the first entry for a
//!   name;
//! - keeps reading when Android would refuse the package, and records each such case as an
//!   [`Anomaly`] with [`AnomalyKind::rejected_by_android`], because malformed packages target
//!   other parsers and analysis tools too.
//!
//! MobSF extracts packages with Python's `zipfile`, which is more lenient and writes to disk.
//! msec reads the same content without extracting; see `docs/PORTING.md`.

mod anomaly;
mod entries;
mod error;
mod format;
mod inflate;
mod layout;
mod limits;
mod locate;
mod names;

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::ops::Range;
use std::path::Path;

pub use anomaly::{Anomaly, AnomalyKind, LocalHeaderField, NameIssue};
pub use error::ArchiveError;
pub use limits::Limits;

use inflate::InflateError;

/// Largest single [`ZipArchive::read_raw`] request; callers read big regions in chunks.
pub const MAX_RAW_READ: u64 = 16 * 1024 * 1024;
use locate::CentralDirectoryLocation;

/// One entry from the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Position in the central directory.
    pub index: usize,
    /// Name as lossy UTF-8. Use [`Entry::raw_name`] when exact bytes matter.
    pub name: String,
    /// Name bytes exactly as stored.
    pub raw_name: Vec<u8>,
    /// Compression method (0 stored, 8 deflate; anything else cannot be read).
    pub method: u16,
    /// General purpose bit flags.
    pub flags: u16,
    /// CRC-32 declared in the central directory.
    pub crc32: u32,
    /// Compressed size declared in the central directory.
    pub compressed_size: u64,
    /// Uncompressed size declared in the central directory.
    pub uncompressed_size: u64,
    /// Local header offset declared in the central directory.
    pub local_header_offset: u64,
    /// Unix mode bits, when the archive was made on Unix.
    pub unix_mode: Option<u32>,
    /// Name ends with `/`.
    pub is_directory: bool,
    /// Unix symbolic link. Its content is the link target; msec never follows it.
    pub is_symlink: bool,
    /// File position of the data, when the local header could be located.
    data_offset: Option<u64>,
}

impl Entry {
    /// True when the entry's data can be located (its local header exists and is in bounds).
    pub fn is_readable(&self) -> bool {
        self.data_offset.is_some()
    }

    /// File offset of the entry's data, when its local header could be located.
    pub fn data_offset(&self) -> Option<u64> {
        self.data_offset
    }

    /// A readable stored file entry, for unit tests of analyses that only look at names and
    /// sizes.
    #[cfg(test)]
    pub(crate) fn for_test(index: usize, name: &str, uncompressed_size: u64) -> Self {
        Self {
            index,
            name: name.to_owned(),
            raw_name: name.as_bytes().to_vec(),
            method: format::METHOD_STORED,
            flags: 0,
            crc32: 0,
            compressed_size: uncompressed_size,
            uncompressed_size,
            local_header_offset: 0,
            unix_mode: None,
            is_directory: name.ends_with('/'),
            is_symlink: false,
            data_offset: Some(0),
        }
    }
}

/// Where the archive's structures are in the file. Used by signature verification, which
/// hashes these regions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveLayout {
    /// Size of the file.
    pub archive_bytes: u64,
    /// Bytes prepended without adjusting offsets; added to every declared offset.
    pub shift: u64,
    /// File position of the central directory.
    pub central_directory_offset: u64,
    /// Size of the central directory.
    pub central_directory_size: u64,
    /// File position of the classic end of central directory record.
    pub end_record_offset: u64,
    /// The archive uses ZIP64 end records.
    pub zip64: bool,
    /// The APK Signing Block (v2+ signatures), when present directly before the central
    /// directory.
    pub apk_signing_block: Option<Range<u64>>,
}

/// An opened archive. Entries are listed at open time; data is read on demand.
pub struct ZipArchive<R> {
    reader: R,
    limits: Limits,
    entries: Vec<Entry>,
    anomalies: Vec<Anomaly>,
    layout: ArchiveLayout,
    /// Output bytes produced by all reads so far, for [`Limits::max_total_bytes`].
    bytes_produced: u64,
    /// Entries whose read-time checks (CRC, size) were already recorded.
    read_checked: Vec<bool>,
}

impl ZipArchive<BufReader<File>> {
    /// Opens the archive at `path`.
    pub fn open_path(path: impl AsRef<Path>, limits: Limits) -> Result<Self, ArchiveError> {
        Self::open(BufReader::new(File::open(path)?), limits)
    }
}

impl<R: Read + Seek> ZipArchive<R> {
    /// Reads the central directory, checks every local header and records anomalies.
    pub fn open(mut reader: R, limits: Limits) -> Result<Self, ArchiveError> {
        let archive_bytes = reader.seek(SeekFrom::End(0))?;
        if archive_bytes > limits.max_archive_bytes {
            return Err(ArchiveError::ArchiveTooLarge {
                bytes: archive_bytes,
                limit: limits.max_archive_bytes,
            });
        }
        let mut anomalies = Vec::new();
        let location =
            locate::locate_central_directory(&mut reader, archive_bytes, &limits, &mut anomalies)?;
        let central_directory = read_exact_at(&mut reader, location.offset, location.size)?;
        let records =
            entries::parse_central_directory(&central_directory, &location, &mut anomalies)?;
        drop(central_directory);

        let mut extents = Vec::with_capacity(records.len());
        let entries = entries::build_entries(
            &mut reader,
            records,
            &location,
            &mut anomalies,
            &mut extents,
        )?;
        let apk_signing_block = layout::find_apk_signing_block(&mut reader, location.offset)?;
        anomalies.extend(layout::layout_anomalies(
            &entries,
            extents,
            apk_signing_block.as_ref(),
            &location,
        ));

        Ok(Self {
            reader,
            limits,
            read_checked: vec![false; entries.len()],
            entries,
            anomalies,
            layout: archive_layout(archive_bytes, &location, apk_signing_block),
            bytes_produced: 0,
        })
    }

    /// All entries, in central directory order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Anomalies found so far: structural ones at open time, data ones (CRC, size) as entries
    /// are read.
    pub fn anomalies(&self) -> &[Anomaly] {
        &self.anomalies
    }

    /// Where the archive's structures are.
    pub fn layout(&self) -> &ArchiveLayout {
        &self.layout
    }

    /// The first entry with exactly this name, in central directory order. With duplicate
    /// names Android rejects the package, while Python's `zipfile` (and so MobSF) uses the last
    /// one; [`AnomalyKind::DuplicateName`] flags both cases.
    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.raw_name == name.as_bytes())
    }

    /// Reads and decompresses one entry, within the limits. A CRC or size mismatch does not
    /// fail the read; it is recorded in [`ZipArchive::anomalies`].
    pub fn read(&mut self, index: usize) -> Result<Vec<u8>, ArchiveError> {
        let entry = self
            .entries
            .get(index)
            .ok_or(ArchiveError::NoSuchEntry { index })?;
        let plan = ReadPlan::for_entry(entry)?;
        let (cap, binding_limit) = self.output_cap(plan.compressed_size);

        self.reader.seek(SeekFrom::Start(plan.data_offset))?;
        let compressed = (&mut self.reader).take(plan.compressed_size);
        let result = inflate::inflate_bounded(compressed, plan.method, cap, plan.uncompressed_size);
        match result {
            Ok(data) => {
                self.bytes_produced += data.len() as u64;
                self.record_read_checks(index, &data);
                Ok(data)
            }
            Err(InflateError::LimitExceeded { produced }) => {
                self.bytes_produced += produced;
                Err(binding_limit.into_error(self.entries[index].name.clone(), &self.limits))
            }
            Err(InflateError::Corrupt { produced }) => {
                self.bytes_produced += produced;
                Err(ArchiveError::CorruptData {
                    name: self.entries[index].name.clone(),
                })
            }
            Err(InflateError::Io(error)) => Err(ArchiveError::Io(error)),
        }
    }

    /// Reads the first entry with this name; `Ok(None)` when there is none.
    pub fn read_by_name(&mut self, name: &str) -> Result<Option<Vec<u8>>, ArchiveError> {
        match self.find(name).map(|entry| entry.index) {
            Some(index) => self.read(index).map(Some),
            None => Ok(None),
        }
    }

    /// Reads raw file bytes (no decompression), for analyses that hash or parse file regions:
    /// the APK Signing Block, signature content digests. At most [`MAX_RAW_READ`] bytes per call;
    /// the range must lie inside the file.
    pub fn read_raw(&mut self, offset: u64, length: u64) -> Result<Vec<u8>, ArchiveError> {
        let end = offset.checked_add(length);
        if length > MAX_RAW_READ || end.is_none_or(|end| end > self.layout.archive_bytes) {
            return Err(ArchiveError::InvalidCentralDirectory(
                "raw read outside the file",
            ));
        }
        read_exact_at(&mut self.reader, offset, length)
    }

    /// Returns the underlying reader, for analyses that need raw file regions (the APK
    /// Signing Block, for example).
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// The most this read may produce, and which limit sets it.
    fn output_cap(&self, compressed_size: u64) -> (u64, OutputLimit) {
        let ratio_cap = compressed_size
            .saturating_mul(self.limits.max_compression_ratio)
            .max(self.limits.ratio_check_after_bytes);
        let remaining_total = self
            .limits
            .max_total_bytes
            .saturating_sub(self.bytes_produced);
        [
            (remaining_total, OutputLimit::Total),
            (self.limits.max_entry_bytes, OutputLimit::Entry),
            (ratio_cap, OutputLimit::Ratio),
        ]
        .into_iter()
        .min_by_key(|(bytes, _)| *bytes)
        .unwrap_or((0, OutputLimit::Total))
    }

    fn record_read_checks(&mut self, index: usize, data: &[u8]) {
        if std::mem::replace(&mut self.read_checked[index], true) {
            return;
        }
        let entry = &self.entries[index];
        let actual = data.len() as u64;
        let mut found = Vec::new();
        if actual != entry.uncompressed_size {
            found.push(AnomalyKind::DeclaredSizeMismatch {
                declared: entry.uncompressed_size,
                actual,
            });
        }
        if crc32fast::hash(data) != entry.crc32 {
            found.push(AnomalyKind::CrcMismatch);
        }
        let name = entry.name.clone();
        self.anomalies.extend(found.into_iter().map(|kind| Anomaly {
            kind,
            entry: Some(name.clone()),
        }));
    }
}

/// What one read needs from an entry, checked before any I/O.
struct ReadPlan {
    data_offset: u64,
    method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
}

impl ReadPlan {
    fn for_entry(entry: &Entry) -> Result<Self, ArchiveError> {
        let data_offset = entry
            .data_offset
            .ok_or_else(|| ArchiveError::UnreadableEntry {
                name: entry.name.clone(),
            })?;
        if !entries::is_supported_method(entry.method) {
            return Err(ArchiveError::UnsupportedCompression {
                name: entry.name.clone(),
                method: entry.method,
            });
        }
        Ok(Self {
            data_offset,
            method: entry.method,
            compressed_size: entry.compressed_size,
            uncompressed_size: entry.uncompressed_size,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum OutputLimit {
    Total,
    Entry,
    Ratio,
}

impl OutputLimit {
    fn into_error(self, name: String, limits: &Limits) -> ArchiveError {
        match self {
            Self::Total => ArchiveError::TotalBudgetExceeded {
                limit: limits.max_total_bytes,
            },
            Self::Entry => ArchiveError::EntryTooLarge {
                name,
                limit: limits.max_entry_bytes,
            },
            Self::Ratio => ArchiveError::CompressionRatioExceeded {
                name,
                limit: limits.max_compression_ratio,
            },
        }
    }
}

fn archive_layout(
    archive_bytes: u64,
    location: &CentralDirectoryLocation,
    apk_signing_block: Option<Range<u64>>,
) -> ArchiveLayout {
    ArchiveLayout {
        archive_bytes,
        shift: location.shift,
        central_directory_offset: location.offset,
        central_directory_size: location.size,
        end_record_offset: location.end_record_offset,
        zip64: location.zip64,
        apk_signing_block,
    }
}

/// Reads exactly `length` bytes at `offset`. Callers bound `length` by a limit or a format
/// maximum before calling.
fn read_exact_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, ArchiveError> {
    let length = usize::try_from(length)
        .map_err(|_| ArchiveError::InvalidCentralDirectory("length does not fit in memory"))?;
    reader.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0; length];
    reader.read_exact(&mut buffer)?;
    Ok(buffer)
}
