//! Bounded decompression of one entry's data.

use std::io::{self, Read};

use flate2::read::DeflateDecoder;

use super::format::{METHOD_DEFLATE, METHOD_STORED};

/// Never reserve more than this up front, whatever the entry declares: the declared size is
/// attacker-controlled.
const PREALLOCATION_LIMIT: u64 = 16 * 1024 * 1024;

pub(super) enum InflateError {
    /// More than `cap` bytes came out. `produced` counts what was decompressed before stopping.
    LimitExceeded {
        produced: u64,
    },
    /// The compressed stream is invalid.
    Corrupt {
        produced: u64,
    },
    Io(io::Error),
}

/// Decompresses `compressed` (already limited to the entry's compressed size) and fails as
/// soon as the output exceeds `cap` bytes, so a decompression bomb costs at most `cap + 1`.
pub(super) fn inflate_bounded<R: Read>(
    compressed: R,
    method: u16,
    cap: u64,
    declared_size: u64,
) -> Result<Vec<u8>, InflateError> {
    let capacity = declared_size.min(cap).min(PREALLOCATION_LIMIT);
    let mut output = Vec::with_capacity(usize::try_from(capacity).unwrap_or(0));
    let read_limit = cap.saturating_add(1);
    let result = match method {
        METHOD_STORED => compressed.take(read_limit).read_to_end(&mut output),
        METHOD_DEFLATE => DeflateDecoder::new(compressed)
            .take(read_limit)
            .read_to_end(&mut output),
        // Callers check the method first; reaching this is a bug, reported as corrupt data
        // rather than a panic.
        _ => return Err(InflateError::Corrupt { produced: 0 }),
    };
    let produced = output.len() as u64;
    match result {
        Ok(_) if produced > cap => Err(InflateError::LimitExceeded { produced }),
        Ok(_) => Ok(output),
        Err(error) if is_stream_error(&error) => Err(InflateError::Corrupt { produced }),
        Err(error) => Err(InflateError::Io(error)),
    }
}

/// flate2 reports a malformed deflate stream as `InvalidInput` or `InvalidData`; a stream cut
/// short by the compressed-size limit surfaces as `UnexpectedEof`.
fn is_stream_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    )
}
