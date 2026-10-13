//! Magic-byte checks applied to a package before analysis.
//!
//! Ported from `is_zip_magic`, `is_elf_so_magic`, `is_dylib_magic` and `is_a_magic` in
//! MobSF `mobsf/MobSF/utils.py` (v4.5.3). Each check looks at the first four bytes only, exactly
//! as upstream does; a buffer shorter than four bytes never matches.

/// Local file header signature `PK\x03\x04`. Spanned and empty archives are not accepted,
/// matching upstream.
const ZIP_LOCAL_FILE_HEADER: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const ELF: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];

/// Mach-O and fat (universal) binary signatures accepted for `.dylib` uploads.
const DYLIB_MAGICS: [[u8; 4]; 6] = [
    [0xCA, 0xFE, 0xBA, 0xBE], // fat, 32-bit
    [0xFE, 0xED, 0xFA, 0xCE], // Mach-O 32-bit, big endian
    [0xCE, 0xFA, 0xED, 0xFE], // Mach-O 32-bit, little endian
    [0xFE, 0xED, 0xFA, 0xCF], // Mach-O 64-bit, big endian
    [0xCF, 0xFA, 0xED, 0xFE], // Mach-O 64-bit, little endian
    [0xCA, 0xFE, 0xBA, 0xBF], // fat, 64-bit
];

/// Signatures accepted for `.a` static libraries: `!<ar` archives and fat binaries.
const STATIC_LIBRARY_MAGICS: [[u8; 4]; 3] = [
    [0x21, 0x3C, 0x61, 0x72], // "!<ar"
    [0xCA, 0xFE, 0xBA, 0xBF], // fat, 64-bit
    [0xCA, 0xFE, 0xBA, 0xBE], // fat, 32-bit
];

fn first_four_bytes(bytes: &[u8]) -> Option<[u8; 4]> {
    bytes.get(..4)?.try_into().ok()
}

/// True when `bytes` starts with a ZIP local file header (APK, AAB, IPA, JAR, AAR, XAPK, APKS,
/// source ZIP).
pub fn is_zip(bytes: &[u8]) -> bool {
    first_four_bytes(bytes) == Some(ZIP_LOCAL_FILE_HEADER)
}

/// True when `bytes` starts with the ELF signature (`.so` uploads).
pub fn is_elf(bytes: &[u8]) -> bool {
    first_four_bytes(bytes) == Some(ELF)
}

/// True when `bytes` starts with a Mach-O or fat-binary signature (`.dylib` uploads).
pub fn is_dylib(bytes: &[u8]) -> bool {
    first_four_bytes(bytes).is_some_and(|magic| DYLIB_MAGICS.contains(&magic))
}

/// True when `bytes` starts with an `ar` archive or fat-binary signature (`.a` uploads).
pub fn is_static_library(bytes: &[u8]) -> bool {
    first_four_bytes(bytes).is_some_and(|magic| STATIC_LIBRARY_MAGICS.contains(&magic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_requires_local_file_header_signature() {
        assert!(is_zip(b"PK\x03\x04rest-of-archive"));
        assert!(!is_zip(b"PK\x05\x06")); // empty archive: rejected like upstream
        assert!(!is_zip(b"PK\x03"));
        assert!(!is_zip(b""));
    }

    #[test]
    fn elf_signature() {
        assert!(is_elf(b"\x7FELF\x02\x01\x01"));
        assert!(!is_elf(b"\x7FEL"));
    }

    #[test]
    fn dylib_accepts_thin_and_fat_mach_o() {
        assert!(is_dylib(&[0xCF, 0xFA, 0xED, 0xFE, 0x0C]));
        assert!(is_dylib(&[0xCA, 0xFE, 0xBA, 0xBE]));
        assert!(!is_dylib(b"!<arch>\n"));
    }

    #[test]
    fn static_library_accepts_ar_and_fat() {
        assert!(is_static_library(b"!<arch>\n"));
        assert!(is_static_library(&[0xCA, 0xFE, 0xBA, 0xBF]));
        assert!(!is_static_library(&[0xCF, 0xFA, 0xED, 0xFE]));
    }
}
