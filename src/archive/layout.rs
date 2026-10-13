//! Whole-file layout: unaccounted bytes, overlapping entries and the APK Signing Block.

use std::io::{Read, Seek};
use std::ops::Range;

use super::anomaly::{Anomaly, AnomalyKind};
use super::error::ArchiveError;
use super::format::APK_SIGNING_BLOCK_MAGIC;
use super::locate::CentralDirectoryLocation;
use super::{Entry, read_exact_at};

/// The block's own leading size field, plus its trailing size field and magic.
const SIGNING_BLOCK_MIN_BYTES: u64 = 8 + 8 + 16;

/// Finds the APK Signing Block (APK Signature Scheme v2 and later) directly before the
/// central directory. Its contents are parsed by the signing analysis, not here.
pub(super) fn find_apk_signing_block<R: Read + Seek>(
    reader: &mut R,
    central_directory_offset: u64,
) -> Result<Option<Range<u64>>, ArchiveError> {
    if central_directory_offset < SIGNING_BLOCK_MIN_BYTES {
        return Ok(None);
    }
    let footer = read_exact_at(reader, central_directory_offset - 24, 24)?;
    if footer[8..] != APK_SIGNING_BLOCK_MAGIC[..] {
        return Ok(None);
    }
    // The size fields exclude the leading size field itself.
    let size = le_u64(&footer[..8]);
    let Some(start) = size
        .checked_add(8)
        .and_then(|total| central_directory_offset.checked_sub(total))
    else {
        return Ok(None);
    };
    if size < SIGNING_BLOCK_MIN_BYTES - 8 || le_u64(&read_exact_at(reader, start, 8)?) != size {
        return Ok(None);
    }
    Ok(Some(start..central_directory_offset))
}

fn le_u64(bytes: &[u8]) -> u64 {
    let mut array = [0; 8];
    array.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(array)
}

/// Walks the readable entries in file order and reports gaps and overlaps. The region before
/// the central directory must be covered by entries, then optionally the signing block;
/// nothing may sit between the central directory and the end records.
pub(super) fn layout_anomalies(
    entries: &[Entry],
    mut extents: Vec<(usize, Range<u64>)>,
    signing_block: Option<&Range<u64>>,
    location: &CentralDirectoryLocation,
) -> Vec<Anomaly> {
    extents.sort_by_key(|(_, range)| (range.start, range.end));
    let mut anomalies = Vec::new();
    let mut covered_until = 0;
    let mut furthest_entry: Option<usize> = None;
    for (index, range) in &extents {
        if range.start > covered_until {
            anomalies.push(gap_anomaly(
                covered_until,
                range.start - covered_until,
                !entries.is_empty(),
            ));
        } else if range.start < covered_until
            && let Some(other) = furthest_entry
        {
            anomalies.push(Anomaly {
                kind: AnomalyKind::OverlappingData {
                    other: entries[other].name.clone(),
                },
                entry: Some(entries[*index].name.clone()),
            });
        }
        if range.end > covered_until {
            covered_until = range.end;
            furthest_entry = Some(*index);
        }
    }

    let entries_region_end = signing_block.map_or(location.offset, |block| block.start);
    if covered_until < entries_region_end {
        anomalies.push(gap_anomaly(
            covered_until,
            entries_region_end - covered_until,
            !entries.is_empty(),
        ));
    }
    let directory_end = location.offset + location.size;
    if directory_end < location.trailer_offset {
        anomalies.push(gap_anomaly(
            directory_end,
            location.trailer_offset - directory_end,
            false,
        ));
    }
    anomalies
}

/// Bytes at the very start of a non-empty archive break Android's rule that the file starts
/// with a local file header; anywhere else they are hidden data.
fn gap_anomaly(offset: u64, bytes: u64, archive_has_entries: bool) -> Anomaly {
    let kind = if offset == 0 && archive_has_entries {
        AnomalyKind::DataBeforeFirstEntry { bytes }
    } else {
        AnomalyKind::HiddenData { offset, bytes }
    };
    Anomaly { kind, entry: None }
}
