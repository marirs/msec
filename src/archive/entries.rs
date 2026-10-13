//! Central directory records turned into entries, each checked against its local file header.

use std::collections::HashSet;
use std::io::{Read, Seek};
use std::ops::Range;

use super::anomaly::{Anomaly, AnomalyKind, LocalHeaderField};
use super::error::ArchiveError;
use super::format::{
    CentralDirectoryRecord, DATA_DESCRIPTOR_SIGNATURE, FLAG_DATA_DESCRIPTOR, FLAG_ENCRYPTED,
    LOCAL_FILE_HEADER_LENGTH, LOCAL_FILE_HEADER_SIGNATURE, LocalFileHeader, METHOD_DEFLATE,
    METHOD_STORED, local_sizes_are_zip64,
};
use super::locate::CentralDirectoryLocation;
use super::names::name_anomalies;
use super::{Entry, read_exact_at};

const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;
const UNIX_SYMLINK: u32 = 0o120_000;

/// Splits the central directory into records. A malformed record stops the whole archive,
/// as it does on Android: the offsets of every later record are unknown.
pub(super) fn parse_central_directory(
    central_directory: &[u8],
    location: &CentralDirectoryLocation,
    anomalies: &mut Vec<Anomaly>,
) -> Result<Vec<CentralDirectoryRecord>, ArchiveError> {
    // total_entries is bounded by Limits::max_entries before this point.
    let mut records = Vec::with_capacity(location.total_entries as usize);
    let mut position = 0;
    for _ in 0..location.total_entries {
        let record = central_directory
            .get(position..)
            .and_then(CentralDirectoryRecord::parse)
            .ok_or(ArchiveError::InvalidCentralDirectory(
                "malformed central directory record",
            ))?;
        position += record.record_length;
        records.push(record);
    }
    if position < central_directory.len() {
        anomalies.push(Anomaly {
            kind: AnomalyKind::HiddenData {
                offset: location.offset + position as u64,
                bytes: (central_directory.len() - position) as u64,
            },
            entry: None,
        });
    }
    Ok(records)
}

/// Builds entries and records per-entry anomalies. `extents` receives the bytes each readable
/// entry occupies (local header, data and data descriptor) for the layout check.
pub(super) fn build_entries<R: Read + Seek>(
    reader: &mut R,
    records: Vec<CentralDirectoryRecord>,
    location: &CentralDirectoryLocation,
    anomalies: &mut Vec<Anomaly>,
    extents: &mut Vec<(usize, Range<u64>)>,
) -> Result<Vec<Entry>, ArchiveError> {
    let mut seen_names = HashSet::with_capacity(records.len());
    let mut entries = Vec::with_capacity(records.len());
    for (index, record) in records.into_iter().enumerate() {
        let name = String::from_utf8_lossy(&record.raw_name).into_owned();
        let mut entry_anomalies = record_anomalies(&record, &mut seen_names);
        let check = check_local_header(reader, &record, location)?;
        entry_anomalies.extend(check.anomalies);
        if let Some(extent) = &check.extent {
            extents.push((index, extent.occupied.clone()));
        }
        anomalies.extend(entry_anomalies.into_iter().map(|kind| Anomaly {
            kind,
            entry: Some(name.clone()),
        }));
        entries.push(entry_from_record(
            index,
            name,
            record,
            check.extent.map(|extent| extent.data_offset),
        ));
    }
    Ok(entries)
}

/// Anomalies visible from the central directory record alone.
fn record_anomalies(
    record: &CentralDirectoryRecord,
    seen_names: &mut HashSet<Vec<u8>>,
) -> Vec<AnomalyKind> {
    let mut anomalies = name_anomalies(&record.raw_name);
    // Raw bytes, as Android compares them.
    if !seen_names.insert(record.raw_name.clone()) {
        anomalies.push(AnomalyKind::DuplicateName);
    }
    if record.flags & FLAG_ENCRYPTED != 0 {
        anomalies.push(AnomalyKind::EncryptionFlagSet);
    }
    if !is_supported_method(record.method) {
        anomalies.push(AnomalyKind::UnsupportedCompression {
            method: record.method,
        });
    }
    if is_symlink(record) {
        anomalies.push(AnomalyKind::Symlink);
    }
    anomalies
}

pub(super) fn is_supported_method(method: u16) -> bool {
    method == METHOD_STORED || method == METHOD_DEFLATE
}

fn is_symlink(record: &CentralDirectoryRecord) -> bool {
    record
        .unix_mode()
        .is_some_and(|mode| mode & UNIX_FILE_TYPE_MASK == UNIX_SYMLINK)
}

fn entry_from_record(
    index: usize,
    name: String,
    record: CentralDirectoryRecord,
    data_offset: Option<u64>,
) -> Entry {
    Entry {
        index,
        name,
        is_directory: record.raw_name.ends_with(b"/"),
        is_symlink: is_symlink(&record),
        unix_mode: record.unix_mode(),
        method: record.method,
        flags: record.flags,
        crc32: record.crc32,
        compressed_size: record.compressed_size,
        uncompressed_size: record.uncompressed_size,
        local_header_offset: record.local_header_offset,
        raw_name: record.raw_name,
        data_offset,
    }
}

/// Where a readable entry's data is.
struct EntryExtent {
    data_offset: u64,
    /// From the local header to the end of the data descriptor, if any.
    occupied: Range<u64>,
}

struct LocalHeaderCheck {
    /// `None` when the data cannot be located; the entry is then unreadable.
    extent: Option<EntryExtent>,
    anomalies: Vec<AnomalyKind>,
}

impl LocalHeaderCheck {
    fn unreadable(kind: AnomalyKind) -> Self {
        Self {
            extent: None,
            anomalies: vec![kind],
        }
    }
}

/// Compares the local header with the central directory the way Android's `FindEntry` does.
/// Unlike Android, a name, CRC or size mismatch does not make the entry unreadable: the data
/// can still be located, and the anomaly is reported instead.
fn check_local_header<R: Read + Seek>(
    reader: &mut R,
    record: &CentralDirectoryRecord,
    location: &CentralDirectoryLocation,
) -> Result<LocalHeaderCheck, ArchiveError> {
    let limit = location.offset;
    let Some(header_offset) = record.local_header_offset.checked_add(location.shift) else {
        return Ok(LocalHeaderCheck::unreadable(AnomalyKind::DataOutOfBounds));
    };
    let fixed_end = header_offset.saturating_add(LOCAL_FILE_HEADER_LENGTH as u64);
    if fixed_end > limit {
        return Ok(LocalHeaderCheck::unreadable(AnomalyKind::DataOutOfBounds));
    }
    let fixed = read_exact_at(reader, header_offset, LOCAL_FILE_HEADER_LENGTH as u64)?;
    if !fixed.starts_with(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes()) {
        return Ok(LocalHeaderCheck::unreadable(signature_mismatch()));
    }
    let Some(name_length) = LocalFileHeader::declared_name_length(&fixed) else {
        return Ok(LocalHeaderCheck::unreadable(signature_mismatch()));
    };
    let header_bytes = (LOCAL_FILE_HEADER_LENGTH + name_length) as u64;
    if header_offset.saturating_add(header_bytes) > limit {
        return Ok(LocalHeaderCheck::unreadable(AnomalyKind::DataOutOfBounds));
    }
    let bytes = read_exact_at(reader, header_offset, header_bytes)?;
    let Some(local) = LocalFileHeader::parse(&bytes) else {
        return Ok(LocalHeaderCheck::unreadable(signature_mismatch()));
    };

    let anomalies = header_field_mismatches(record, &local);
    let data_offset = header_offset + header_bytes + local.extra_length as u64;
    let Some(data_end) = data_offset
        .checked_add(record.compressed_size)
        .filter(|&end| end <= limit)
    else {
        let mut anomalies = anomalies;
        anomalies.push(AnomalyKind::DataOutOfBounds);
        return Ok(LocalHeaderCheck {
            extent: None,
            anomalies,
        });
    };
    let descriptor_length = data_descriptor_length(reader, record, &local, data_end, limit)?;
    Ok(LocalHeaderCheck {
        extent: Some(EntryExtent {
            data_offset,
            occupied: header_offset..(data_end + descriptor_length).min(limit),
        }),
        anomalies,
    })
}

fn signature_mismatch() -> AnomalyKind {
    AnomalyKind::LocalHeaderMismatch {
        field: LocalHeaderField::Signature,
    }
}

fn header_field_mismatches(
    record: &CentralDirectoryRecord,
    local: &LocalFileHeader,
) -> Vec<AnomalyKind> {
    let mut fields = Vec::new();
    if local.raw_name != record.raw_name {
        fields.push(LocalHeaderField::Name);
    }
    if local.method != record.method {
        fields.push(LocalHeaderField::Method);
    }
    if (local.flags ^ record.flags) & FLAG_DATA_DESCRIPTOR != 0 {
        fields.push(LocalHeaderField::DataDescriptorFlag);
    }
    // Android decides from the local flag whether the local values are meaningful.
    if local.flags & FLAG_DATA_DESCRIPTOR == 0 {
        if local.crc32 != record.crc32 {
            fields.push(LocalHeaderField::Crc32);
        }
        if !local_sizes_are_zip64(local) {
            if u64::from(local.compressed_size_32) != record.compressed_size {
                fields.push(LocalHeaderField::CompressedSize);
            }
            if u64::from(local.uncompressed_size_32) != record.uncompressed_size {
                fields.push(LocalHeaderField::UncompressedSize);
            }
        }
    }
    fields
        .into_iter()
        .map(|field| AnomalyKind::LocalHeaderMismatch { field })
        .collect()
}

/// Length of the data descriptor after the data: CRC and two sizes (4 or 8 bytes each),
/// optionally preceded by a signature.
fn data_descriptor_length<R: Read + Seek>(
    reader: &mut R,
    record: &CentralDirectoryRecord,
    local: &LocalFileHeader,
    data_end: u64,
    limit: u64,
) -> Result<u64, ArchiveError> {
    if local.flags & FLAG_DATA_DESCRIPTOR == 0 {
        return Ok(0);
    }
    let zip64 = local_sizes_are_zip64(local)
        || record.compressed_size >= u64::from(u32::MAX)
        || record.uncompressed_size >= u64::from(u32::MAX);
    let body = if zip64 { 4 + 8 + 8 } else { 4 + 4 + 4 };
    let has_signature = data_end + 4 <= limit
        && read_exact_at(reader, data_end, 4)? == DATA_DESCRIPTOR_SIGNATURE.to_le_bytes();
    // Deferred: Android also compares the descriptor's CRC and sizes with the central
    // directory when the entry is extracted.
    Ok(if has_signature { body + 4 } else { body })
}
