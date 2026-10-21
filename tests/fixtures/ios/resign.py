"""Re-signs a thin arm64 Mach-O executable, already signed ad hoc by codesign, with a
certificate: the same requirements, entitlements and special-slot hashes (the bundle's
Info.plist and CodeResources seal), a CodeDirectory that names a team and is no longer ad hoc,
page hashes recomputed, and a detached CMS signature over that CodeDirectory made by OpenSSL.

This is what `codesign -s <identity>` writes, made without a keychain: codesign only signs with
identities in the user's keychain search list, which fixtures must not touch. Apple's codesign
reads the result back as the oracle (build_certificate_signed.sh).

    python3 -I resign.py <executable> <leaf.pem> <leaf.key> <chain.pem> <team> [--tamper-cms]

OPENSSL names an OpenSSL 3 binary (LibreSSL has no cms command). --tamper-cms flips the last byte of the CMS signature (inside the signer's signature value),
so the signature no longer verifies while everything it signs is intact.
"""

import hashlib
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19
SUPERBLOB = 0xFADE0CC0
CODE_DIRECTORY = 0xFADE0C02
BLOB_WRAPPER = 0xFADE0B01
SLOT_CODE_DIRECTORY = 0
SLOT_CMS = 0x10000
CS_ADHOC = 0x2
CD_HEADER_20400 = 88
# Room for the new signature; the load commands are written for this size before the pages
# are hashed, so the CodeDirectory never has to be redone once the CMS signature is known.
SIGNATURE_SPACE = 16384
LINKEDIT_ALIGN = 0x4000


def load_commands(data):
    magic, _, _, _, ncmds = struct.unpack_from("<IiiII", data, 0)
    if magic != 0xFEEDFACF:
        raise SystemExit("not a thin 64-bit little-endian Mach-O")
    offset = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, offset)
        yield cmd, offset
        offset += size


def blobs(superblob):
    magic, _, count = struct.unpack_from(">III", superblob, 0)
    if magic != SUPERBLOB:
        raise SystemExit("not a code signature superblob")
    for index in range(count):
        slot, offset = struct.unpack_from(">II", superblob, 12 + 8 * index)
        _, length = struct.unpack_from(">II", superblob, offset)
        yield slot, superblob[offset : offset + length]


def code_directory(old, team, image, code_limit):
    version, flags, hash_offset, ident_offset, special, _code, _limit = struct.unpack_from(
        ">IIIIIII", old, 8
    )
    hash_size, hash_type, platform, page_log2 = struct.unpack_from(">BBBB", old, 36)
    if version != 0x20400 or hash_type != 2:
        raise SystemExit(f"expected a v0x20400 SHA-256 CodeDirectory, got {version:#x}")
    identifier = old[ident_offset : old.index(b"\0", ident_offset)]
    specials = old[hash_offset - special * hash_size : hash_offset]
    page = 1 << page_log2
    pages = [
        hashlib.sha256(image[start : min(start + page, code_limit)]).digest()
        for start in range(0, code_limit, page)
    ]
    header = bytearray(old[:CD_HEADER_20400])
    ident_at = CD_HEADER_20400
    team_at = ident_at + len(identifier) + 1
    hashes_at = team_at + len(team) + 1 + len(specials)
    length = hashes_at + len(pages) * hash_size
    struct.pack_into(">II", header, 4, length, version)
    struct.pack_into(">IIIII", header, 12, flags & ~CS_ADHOC, hashes_at, ident_at, special, len(pages))
    struct.pack_into(">I", header, 32, code_limit)
    struct.pack_into(">I", header, 48, team_at)
    return (
        bytes(header)
        + identifier
        + b"\0"
        + team.encode()
        + b"\0"
        + specials
        + b"".join(pages)
    )


def cms_signature(directory, leaf, key, chain):
    with tempfile.TemporaryDirectory() as work:
        content = Path(work) / "cd"
        signature = Path(work) / "cms"
        content.write_bytes(directory)
        subprocess.run(
            [os.environ.get("OPENSSL", "openssl"), "cms", "-sign", "-binary", "-in", str(content), "-signer", leaf,
             "-inkey", key, "-certfile", chain, "-md", "sha256", "-outform", "DER",
             "-out", str(signature)],
            check=True,
        )
        return signature.read_bytes()


def superblob(entries):
    count = len(entries)
    offset = 12 + 8 * count
    index = b""
    body = b""
    for slot, blob in entries:
        index += struct.pack(">II", slot, offset + len(body))
        body += blob
    return struct.pack(">III", SUPERBLOB, 12 + 8 * count + len(body), count) + index + body


def main():
    executable, leaf, key, chain, team = sys.argv[1:6]
    tamper = "--tamper-cms" in sys.argv[6:]
    data = bytearray(Path(executable).read_bytes())
    signature_command = linkedit = None
    for cmd, offset in load_commands(data):
        if cmd == LC_CODE_SIGNATURE:
            signature_command = offset
        if cmd == LC_SEGMENT_64 and data[offset + 8 : offset + 24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit = offset
    data_offset, data_size = struct.unpack_from("<II", data, signature_command + 8)
    old = dict(blobs(bytes(data[data_offset : data_offset + data_size])))
    struct.pack_into("<I", data, signature_command + 12, SIGNATURE_SPACE)
    link_fileoff = struct.unpack_from("<Q", data, linkedit + 40)[0]
    file_size = data_offset + SIGNATURE_SPACE - link_fileoff
    vm_size = (file_size + LINKEDIT_ALIGN - 1) // LINKEDIT_ALIGN * LINKEDIT_ALIGN
    struct.pack_into("<Q", data, linkedit + 32, vm_size)
    struct.pack_into("<Q", data, linkedit + 48, file_size)
    image = bytes(data[:data_offset])
    directory = code_directory(old[SLOT_CODE_DIRECTORY], team, image, data_offset)
    cms = bytearray(cms_signature(directory, leaf, key, chain))
    if tamper:
        cms[-1] ^= 0xFF
    entries = [(SLOT_CODE_DIRECTORY, directory)]
    entries += [(slot, blob) for slot, blob in sorted(old.items())
                if slot not in (SLOT_CODE_DIRECTORY, SLOT_CMS)]
    entries.append((SLOT_CMS, struct.pack(">II", BLOB_WRAPPER, 8 + len(cms)) + bytes(cms)))
    signed = superblob(entries)
    if len(signed) > SIGNATURE_SPACE:
        raise SystemExit(f"signature of {len(signed)} bytes does not fit {SIGNATURE_SPACE}")
    Path(executable).write_bytes(image + signed + bytes(SIGNATURE_SPACE - len(signed)))


if __name__ == "__main__":
    main()
