//! Package digests.
//!
//! MobSF identifies a scan by the MD5 of the uploaded file and reports SHA-1 and SHA-256
//! alongside it (`hash_gen` in `mobsf/StaticAnalyzer/views/common/shared_func.py`, v4.5.3).
//! All three are computed in one streaming pass here.

use std::io::{self, Read};

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Read buffer size; matches upstream's 64 KiB block size.
const READ_BLOCK_BYTES: usize = 64 * 1024;

/// Lower-case hexadecimal digests of a package.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileHashes {
    /// MD5; MobSF uses it as the scan identifier. Not a security property.
    pub md5: String,
    /// SHA-1.
    pub sha1: String,
    /// SHA-256.
    pub sha256: String,
}

impl FileHashes {
    /// Digests of an in-memory buffer.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = StreamingHasher::default();
        hasher.update(bytes);
        hasher.finish()
    }

    /// Digests of everything `reader` yields, read in 64 KiB blocks so large packages are never
    /// held in memory at once.
    pub fn of_reader(mut reader: impl Read) -> io::Result<Self> {
        let mut hasher = StreamingHasher::default();
        let mut block = vec![0u8; READ_BLOCK_BYTES];
        loop {
            let read = match reader.read(&mut block) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            hasher.update(&block[..read]);
        }
        Ok(hasher.finish())
    }

    /// Digests of the file at `path`.
    pub fn of_file(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        Self::of_reader(std::fs::File::open(path)?)
    }
}

#[derive(Default)]
struct StreamingHasher {
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
}

impl StreamingHasher {
    fn update(&mut self, bytes: &[u8]) {
        self.md5.update(bytes);
        self.sha1.update(bytes);
        self.sha256.update(bytes);
    }

    fn finish(self) -> FileHashes {
        FileHashes {
            md5: lower_hex(&self.md5.finalize()),
            sha1: lower_hex(&self.sha1.finalize()),
            sha256: lower_hex(&self.sha256.finalize()),
        }
    }
}

fn lower_hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference digests of the ASCII string "abc" (RFC 1321, FIPS 180).
    #[test]
    fn known_answer_for_abc() {
        let hashes = FileHashes::of_bytes(b"abc");
        assert_eq!(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hashes.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn streaming_across_block_boundaries_matches_one_shot() {
        let data: Vec<u8> = (0..(READ_BLOCK_BYTES * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect();
        let streamed = FileHashes::of_reader(io::Cursor::new(&data)).unwrap();
        assert_eq!(streamed, FileHashes::of_bytes(&data));
    }
}
