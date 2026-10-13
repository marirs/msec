//! Resource limits for reading untrusted archives.

/// Upper bounds applied while opening and reading an archive. Declared sizes inside the archive
/// are hints only; these limits are enforced on what is actually read and produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest archive file accepted at all.
    pub max_archive_bytes: u64,
    /// Most central directory entries accepted.
    pub max_entries: usize,
    /// Largest central directory accepted. It is read into memory whole.
    pub max_central_directory_bytes: u64,
    /// Most bytes one entry may decompress to.
    pub max_entry_bytes: u64,
    /// Most bytes all reads from one archive may produce together.
    pub max_total_bytes: u64,
    /// Highest decompressed-to-compressed ratio tolerated once an entry has produced
    /// [`Limits::ratio_check_after_bytes`] bytes. Stops decompression bombs early.
    pub max_compression_ratio: u64,
    /// Output size below which the ratio is not checked (small, highly compressible files such
    /// as all-zero resources are normal).
    pub ratio_check_after_bytes: u64,
}

impl Default for Limits {
    /// Initial defaults (to be tuned against a real corpus): generous enough for large games
    /// and SDK-heavy apps, small enough that a hostile archive cannot exhaust a CI runner.
    fn default() -> Self {
        Self {
            max_archive_bytes: 4 * 1024 * 1024 * 1024,
            max_entries: 200_000,
            max_central_directory_bytes: 128 * 1024 * 1024,
            max_entry_bytes: 512 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
            max_compression_ratio: 1_000,
            ratio_check_after_bytes: 1024 * 1024,
        }
    }
}
