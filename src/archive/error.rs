//! Errors that stop an archive from being opened, or an entry from being read.

use std::fmt;
use std::io;

/// Why an archive could not be opened or an entry could not be read.
#[derive(Debug)]
pub enum ArchiveError {
    /// Reading the underlying file failed.
    Io(io::Error),
    /// The file is larger than [`super::Limits::max_archive_bytes`].
    ArchiveTooLarge {
        /// Size of the file.
        bytes: u64,
        /// The limit it exceeds.
        limit: u64,
    },
    /// No end of central directory record: not a ZIP archive, or truncated.
    NotAnArchive,
    /// The central directory lies outside the file, or its records are malformed.
    InvalidCentralDirectory(&'static str),
    /// The central directory is larger than [`super::Limits::max_central_directory_bytes`].
    CentralDirectoryTooLarge {
        /// Declared size of the central directory.
        bytes: u64,
        /// The limit it exceeds.
        limit: u64,
    },
    /// More entries than [`super::Limits::max_entries`].
    TooManyEntries {
        /// Declared number of entries.
        entries: u64,
        /// The limit it exceeds.
        limit: usize,
    },
    /// The entry's local header is missing or out of bounds, so its data cannot be located.
    UnreadableEntry {
        /// Entry name (lossy UTF-8).
        name: String,
    },
    /// The entry uses a compression method other than stored or deflate.
    UnsupportedCompression {
        /// Entry name (lossy UTF-8).
        name: String,
        /// The compression method number.
        method: u16,
    },
    /// The entry decompresses to more than [`super::Limits::max_entry_bytes`].
    EntryTooLarge {
        /// Entry name (lossy UTF-8).
        name: String,
        /// The limit it exceeds.
        limit: u64,
    },
    /// All reads together exceeded [`super::Limits::max_total_bytes`].
    TotalBudgetExceeded {
        /// The limit that was reached.
        limit: u64,
    },
    /// Decompression exceeded [`super::Limits::max_compression_ratio`] (decompression bomb).
    CompressionRatioExceeded {
        /// Entry name (lossy UTF-8).
        name: String,
        /// The ratio limit.
        limit: u64,
    },
    /// The compressed data is corrupt.
    CorruptData {
        /// Entry name (lossy UTF-8).
        name: String,
    },
    /// No entry with that index.
    NoSuchEntry {
        /// The index asked for.
        index: usize,
    },
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::ArchiveTooLarge { bytes, limit } => {
                write!(
                    formatter,
                    "archive is {bytes} bytes, over the {limit}-byte limit"
                )
            }
            Self::NotAnArchive => write!(formatter, "no ZIP end of central directory record found"),
            Self::InvalidCentralDirectory(reason) => {
                write!(formatter, "invalid central directory: {reason}")
            }
            Self::CentralDirectoryTooLarge { bytes, limit } => write!(
                formatter,
                "central directory is {bytes} bytes, over the {limit}-byte limit"
            ),
            Self::TooManyEntries { entries, limit } => {
                write!(
                    formatter,
                    "archive has {entries} entries, over the limit of {limit}"
                )
            }
            Self::UnreadableEntry { name } => {
                write!(
                    formatter,
                    "entry {name:?} has a missing or out-of-bounds local header"
                )
            }
            Self::UnsupportedCompression { name, method } => {
                write!(
                    formatter,
                    "entry {name:?} uses unsupported compression method {method}"
                )
            }
            Self::EntryTooLarge { name, limit } => {
                write!(
                    formatter,
                    "entry {name:?} decompresses to more than {limit} bytes"
                )
            }
            Self::TotalBudgetExceeded { limit } => {
                write!(
                    formatter,
                    "reads exceeded the {limit}-byte budget for this archive"
                )
            }
            Self::CompressionRatioExceeded { name, limit } => write!(
                formatter,
                "entry {name:?} exceeded the compression ratio limit of {limit}:1"
            ),
            Self::CorruptData { name } => write!(formatter, "entry {name:?} has corrupt data"),
            Self::NoSuchEntry { index } => write!(formatter, "no entry with index {index}"),
        }
    }
}

impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ArchiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
