//! Structural oddities found in an archive. They are evidence, not errors: msec keeps reading
//! so the package can still be analysed, and reports what it saw.

/// Why an entry name is suspicious. Names are never used as file system paths by msec, but
/// these patterns signal hostile intent and can break other tools that do extract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameIssue {
    /// Starts with `/` or a drive letter.
    AbsolutePath,
    /// Contains a `..` path segment (zip-slip).
    ParentTraversal,
    /// Contains `\`, a path separator on Windows.
    Backslash,
    /// Contains ASCII control characters (can inject escape sequences into terminals).
    ControlCharacter,
}

/// A local file header field that disagrees with the central directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalHeaderField {
    /// No local file header signature where the central directory points. The entry's data
    /// cannot be located.
    Signature,
    /// Different name. Android rejects the entry.
    Name,
    /// Different CRC-32 (checked only without a data descriptor). Android rejects the entry.
    Crc32,
    /// Different compressed size (checked only without a data descriptor). Android rejects the
    /// entry.
    CompressedSize,
    /// Different uncompressed size (checked only without a data descriptor). Android rejects
    /// the entry.
    UncompressedSize,
    /// Different compression method. Android uses the central directory value and ignores this,
    /// but tools that walk local headers decompress the entry differently.
    Method,
    /// Disagreement on the data descriptor flag. Android only logs a warning.
    DataDescriptorFlag,
}

impl LocalHeaderField {
    /// True when Android refuses to read the entry over this mismatch.
    pub fn rejected_by_android(self) -> bool {
        !matches!(self, Self::Method | Self::DataDescriptorFlag)
    }
}

/// What kind of structural oddity was found.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    /// Two central directory entries share a name. Android rejects the package; older platform
    /// versions were exploitable through it (CVE-2013-4787, "Master Key").
    DuplicateName,
    /// Bytes precede the first local file header. Android rejects the package; on v1-only
    /// signed APKs this enabled code injection (CVE-2017-13156, "Janus").
    DataBeforeFirstEntry {
        /// Bytes before the first local file header.
        bytes: u64,
    },
    /// Bytes that no entry, signing block or directory structure accounts for.
    HiddenData {
        /// Where the unaccounted bytes start.
        offset: u64,
        /// How many there are.
        bytes: u64,
    },
    /// The entry's stored data overlaps another entry's (used by overlap-based decompression
    /// bombs and by archives that show different content to different parsers).
    OverlappingData {
        /// Name of the entry it overlaps.
        other: String,
    },
    /// Entry name is not valid UTF-8 or contains NUL. Android rejects the package.
    InvalidNameEncoding,
    /// Entry name has a pattern that signals path traversal or terminal injection.
    SuspiciousName(NameIssue),
    /// Entry claims to be encrypted. Android ignores the flag and reads the data as is, so this
    /// is the "fake encryption" trick that breaks some analysis tools.
    EncryptionFlagSet,
    /// Compression method other than stored (0) or deflate (8). Android cannot read the entry.
    UnsupportedCompression {
        /// The compression method number from the central directory.
        method: u16,
    },
    /// Local file header disagrees with the central directory, or is missing.
    LocalHeaderMismatch {
        /// Which field disagrees.
        field: LocalHeaderField,
    },
    /// The entry's local header or data lies outside the space before the central directory.
    /// Android rejects the entry; msec cannot read it.
    DataOutOfBounds,
    /// Entry is a Unix symbolic link. msec never follows it.
    Symlink,
    /// More than one end of central directory signature near the end of the file; different
    /// tools may pick different ones (parser differential).
    MultipleEndRecords,
    /// The archive comment does not end exactly at the end of the file (trailing bytes, or a
    /// truncated comment). Android rejects the package.
    CommentLengthMismatch,
    /// Decompressed data does not match the CRC-32 in the central directory. Android rejects it.
    CrcMismatch,
    /// Entry decompressed to a different size than declared. Android rejects it.
    DeclaredSizeMismatch {
        /// Size in the central directory.
        declared: u64,
        /// Size actually produced.
        actual: u64,
    },
}

impl AnomalyKind {
    /// True when current Android (AOSP `libziparchive`) refuses the package, or refuses the
    /// entry when it reads it. Such packages may still target other parsers, older Android
    /// versions or analysis tools, so msec keeps analysing them.
    pub fn rejected_by_android(&self) -> bool {
        match self {
            Self::LocalHeaderMismatch { field } => field.rejected_by_android(),
            _ => matches!(
                self,
                Self::DuplicateName
                    | Self::DataBeforeFirstEntry { .. }
                    | Self::InvalidNameEncoding
                    | Self::DataOutOfBounds
                    | Self::CommentLengthMismatch
                    | Self::CrcMismatch
                    | Self::DeclaredSizeMismatch { .. }
            ),
        }
    }
}

/// One anomaly, attached to an entry when it concerns one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Anomaly {
    /// What was found.
    pub kind: AnomalyKind,
    /// Entry name (lossy UTF-8), when the anomaly concerns one entry.
    pub entry: Option<String>,
}
