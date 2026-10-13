//! Finding the end record and the central directory, working back from the end of the file.

use std::io::{Read, Seek};

use super::anomaly::{Anomaly, AnomalyKind};
use super::error::ArchiveError;
use super::format::{
    CENTRAL_DIRECTORY_HEADER_LENGTH, CENTRAL_DIRECTORY_SIGNATURE, END_OF_CENTRAL_DIRECTORY_LENGTH,
    EndOfCentralDirectory, MAX_END_RECORD_SEARCH, ZIP64_END_OF_CENTRAL_DIRECTORY_MIN_LENGTH,
    ZIP64_LOCATOR_LENGTH, Zip64EndOfCentralDirectory, parse_zip64_locator,
};
use super::limits::Limits;
use super::read_exact_at;

/// Where the central directory really is, and the structures after it.
#[derive(Debug, Clone, Copy)]
pub(super) struct CentralDirectoryLocation {
    /// File position of the central directory (declared offset plus [`Self::shift`]).
    pub(super) offset: u64,
    pub(super) size: u64,
    pub(super) total_entries: u64,
    /// Bytes added in front of an archive whose offsets were not adjusted (for example
    /// `cat stub.bin app.apk`). Added to every declared offset. Python's `zipfile`, which MobSF
    /// uses, applies the same correction; Android does not and rejects such files.
    pub(super) shift: u64,
    /// File position of the ZIP64 end record when there is one, else of the classic end record.
    /// The central directory must end at or before it.
    pub(super) trailer_offset: u64,
    pub(super) end_record_offset: u64,
    pub(super) zip64: bool,
}

pub(super) fn locate_central_directory<R: Read + Seek>(
    reader: &mut R,
    archive_bytes: u64,
    limits: &Limits,
    anomalies: &mut Vec<Anomaly>,
) -> Result<CentralDirectoryLocation, ArchiveError> {
    let (end_record_offset, end_record) = find_end_record(reader, archive_bytes, anomalies)?;
    let (declared, trailer_offset, zip64) = if end_record.needs_zip64() {
        let (zip64_record, zip64_offset) = read_zip64_end_record(reader, end_record_offset)?;
        (DeclaredDirectory::from(zip64_record), zip64_offset, true)
    } else {
        (
            DeclaredDirectory::from(end_record),
            end_record_offset,
            false,
        )
    };
    check_directory_limits(&declared, limits)?;

    let shift = if zip64 {
        // Deferred: shift recovery for ZIP64 archives (the ZIP64 locator offset would be shifted
        // too). Unshifted ZIP64 archives are read normally.
        0
    } else {
        detect_shift(reader, &declared, trailer_offset)?
    };
    let offset =
        declared
            .offset
            .checked_add(shift)
            .ok_or(ArchiveError::InvalidCentralDirectory(
                "central directory offset overflows",
            ))?;
    let end = offset
        .checked_add(declared.size)
        .ok_or(ArchiveError::InvalidCentralDirectory(
            "central directory size overflows",
        ))?;
    if end > trailer_offset {
        return Err(ArchiveError::InvalidCentralDirectory(
            "central directory extends past the end record",
        ));
    }
    Ok(CentralDirectoryLocation {
        offset,
        size: declared.size,
        total_entries: declared.total_entries,
        shift,
        trailer_offset,
        end_record_offset,
        zip64,
    })
}

/// Picks the end record closest to the end of the file, as Android does, and reports other
/// candidates that would also be self-consistent (a second record hidden in the comment).
fn find_end_record<R: Read + Seek>(
    reader: &mut R,
    archive_bytes: u64,
    anomalies: &mut Vec<Anomaly>,
) -> Result<(u64, EndOfCentralDirectory), ArchiveError> {
    if archive_bytes < END_OF_CENTRAL_DIRECTORY_LENGTH as u64 {
        return Err(ArchiveError::NotAnArchive);
    }
    let tail_length = archive_bytes.min(MAX_END_RECORD_SEARCH as u64);
    let tail_start = archive_bytes - tail_length;
    let tail = read_exact_at(reader, tail_start, tail_length)?;

    let mut candidates = (0..=tail.len() - END_OF_CENTRAL_DIRECTORY_LENGTH)
        .rev()
        .filter_map(|position| {
            EndOfCentralDirectory::parse(&tail[position..])
                .map(|record| (tail_start + position as u64, record))
        });
    let (chosen_offset, chosen) = candidates.next().ok_or(ArchiveError::NotAnArchive)?;
    if end_record_end(chosen_offset, &chosen) != archive_bytes {
        anomalies.push(Anomaly {
            kind: AnomalyKind::CommentLengthMismatch,
            entry: None,
        });
    }
    if candidates.any(|(offset, record)| end_record_end(offset, &record) == archive_bytes) {
        anomalies.push(Anomaly {
            kind: AnomalyKind::MultipleEndRecords,
            entry: None,
        });
    }
    Ok((chosen_offset, chosen))
}

fn end_record_end(offset: u64, record: &EndOfCentralDirectory) -> u64 {
    offset + END_OF_CENTRAL_DIRECTORY_LENGTH as u64 + u64::from(record.comment_length)
}

fn read_zip64_end_record<R: Read + Seek>(
    reader: &mut R,
    end_record_offset: u64,
) -> Result<(Zip64EndOfCentralDirectory, u64), ArchiveError> {
    const MISSING: ArchiveError =
        ArchiveError::InvalidCentralDirectory("ZIP64 end record missing or malformed");
    let locator_offset = end_record_offset
        .checked_sub(ZIP64_LOCATOR_LENGTH as u64)
        .ok_or(MISSING)?;
    let locator = read_exact_at(reader, locator_offset, ZIP64_LOCATOR_LENGTH as u64)?;
    let zip64_offset = parse_zip64_locator(&locator).ok_or(MISSING)?;
    let record_end = zip64_offset
        .checked_add(ZIP64_END_OF_CENTRAL_DIRECTORY_MIN_LENGTH as u64)
        .ok_or(MISSING)?;
    if record_end > locator_offset {
        return Err(MISSING);
    }
    let bytes = read_exact_at(
        reader,
        zip64_offset,
        ZIP64_END_OF_CENTRAL_DIRECTORY_MIN_LENGTH as u64,
    )?;
    let record = Zip64EndOfCentralDirectory::parse(&bytes).ok_or(MISSING)?;
    Ok((record, zip64_offset))
}

/// Central directory values as declared by the classic or ZIP64 end record.
struct DeclaredDirectory {
    offset: u64,
    size: u64,
    total_entries: u64,
}

impl From<EndOfCentralDirectory> for DeclaredDirectory {
    fn from(record: EndOfCentralDirectory) -> Self {
        Self {
            offset: u64::from(record.central_directory_offset),
            size: u64::from(record.central_directory_size),
            total_entries: u64::from(record.total_entries),
        }
    }
}

impl From<Zip64EndOfCentralDirectory> for DeclaredDirectory {
    fn from(record: Zip64EndOfCentralDirectory) -> Self {
        Self {
            offset: record.central_directory_offset,
            size: record.central_directory_size,
            total_entries: record.total_entries,
        }
    }
}

/// Rejects directories that would cost too much memory before anything is allocated.
fn check_directory_limits(
    declared: &DeclaredDirectory,
    limits: &Limits,
) -> Result<(), ArchiveError> {
    if declared.total_entries > limits.max_entries as u64 {
        return Err(ArchiveError::TooManyEntries {
            entries: declared.total_entries,
            limit: limits.max_entries,
        });
    }
    if declared.size > limits.max_central_directory_bytes {
        return Err(ArchiveError::CentralDirectoryTooLarge {
            bytes: declared.size,
            limit: limits.max_central_directory_bytes,
        });
    }
    // Every record has a fixed 46-byte part, so a smaller directory is lying about its count.
    if declared
        .total_entries
        .saturating_mul(CENTRAL_DIRECTORY_HEADER_LENGTH as u64)
        > declared.size
    {
        return Err(ArchiveError::InvalidCentralDirectory(
            "central directory too small for its entry count",
        ));
    }
    Ok(())
}

/// Returns how far the archive was shifted by prepended bytes: zero when the declared offset
/// holds the central directory, else the distance to a central directory that ends exactly
/// at the end record.
fn detect_shift<R: Read + Seek>(
    reader: &mut R,
    declared: &DeclaredDirectory,
    trailer_offset: u64,
) -> Result<u64, ArchiveError> {
    if declared.total_entries == 0
        || starts_central_directory(reader, declared.offset, trailer_offset)?
    {
        return Ok(0);
    }
    let Some(actual_offset) = trailer_offset.checked_sub(declared.size) else {
        return Ok(0);
    };
    if actual_offset > declared.offset
        && starts_central_directory(reader, actual_offset, trailer_offset)?
    {
        return Ok(actual_offset - declared.offset);
    }
    Ok(0)
}

fn starts_central_directory<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    trailer_offset: u64,
) -> Result<bool, ArchiveError> {
    if offset.saturating_add(4) > trailer_offset {
        return Ok(false);
    }
    let signature = read_exact_at(reader, offset, 4)?;
    Ok(signature == CENTRAL_DIRECTORY_SIGNATURE.to_le_bytes())
}
