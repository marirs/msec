//! Strings out of binaries and text out of files.

/// Shortest binary string worth checking: every known format is longer, and MobSF's entropy
/// heuristic needs 21 characters.
const MIN_BINARY_STRING: usize = 8;
/// Bytes sniffed to tell text from binary.
const SNIFF_BYTES: usize = 8192;

/// Runs of printable ASCII (and tabs) of at least [`MIN_BINARY_STRING`] bytes, as `strings`
/// prints them.
pub(crate) fn printable_runs(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&byte| !(byte == b'\t' || (0x20..0x7f).contains(&byte)))
        .filter(|run| run.len() >= MIN_BINARY_STRING)
        .map(|run| String::from_utf8_lossy(run).into_owned())
        .collect()
}

/// The NUL-terminated strings of a C-string section, valid UTF-8 only, of at least
/// [`MIN_BINARY_STRING`] bytes.
pub(crate) fn c_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&byte| byte == 0)
        .filter(|string| string.len() >= MIN_BINARY_STRING)
        .filter_map(|string| std::str::from_utf8(string).ok())
        .map(str::to_owned)
        .collect()
}

/// The file as text: UTF-8 (a byte-order mark dropped) or UTF-16 with a byte-order mark;
/// `None` for binary content (a NUL byte in the first 8 KiB, or invalid UTF-8).
pub(crate) fn as_text(bytes: &[u8]) -> Option<String> {
    if let Some(units) = bytes.strip_prefix(&[0xff, 0xfe]) {
        return utf16(units, u16::from_le_bytes);
    }
    if let Some(units) = bytes.strip_prefix(&[0xfe, 0xff]) {
        return utf16(units, u16::from_be_bytes);
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    if bytes[..bytes.len().min(SNIFF_BYTES)].contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Option<String> {
    let (pairs, _) = bytes.as_chunks::<2>();
    String::from_utf16(&pairs.iter().map(|pair| unit(*pair)).collect::<Vec<u16>>()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_and_text() {
        assert_eq!(
            printable_runs(b"\x00\x01shortish\x00a much longer string\x7f"),
            ["shortish", "a much longer string"]
        );
        assert_eq!(
            c_strings(b"tiny\0long enough\0\xff\xfe broken utf8\0"),
            ["long enough"]
        );
        assert_eq!(
            as_text(b"\xef\xbb\xbfkey=value").as_deref(),
            Some("key=value")
        );
        assert_eq!(as_text(b"\xff\xfek\0=\0v\0").as_deref(), Some("k=v"));
        assert_eq!(as_text(b"PK\x03\x04\0\0"), None);
    }
}
