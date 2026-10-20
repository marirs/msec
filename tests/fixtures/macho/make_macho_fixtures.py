"""Derives msec's edited and hostile Mach-O fixtures from the ones build_macho.sh compiled.

    python3 -I make_macho_fixtures.py <bin-dir> <hostile-dir>

Writes <bin-dir>/encrypted (hardened with cryptid 1, as App Store downloads are),
<bin-dir>/tampered (one byte of code changed after signing), <bin-dir>/stack-exec and
<bin-dir>/no-pie (plain with MH_ALLOW_STACK_EXECUTION set, MH_PIE cleared; build_macho.sh signs
them again), then one file per malformed structure into <hostile-dir>, each changed in one
place from bin/hardened or bin/library.
"""

import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_UUID = 0x1B
LC_RPATH = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C
LC_DATA_IN_CODE = 0x29
LC_DYLD_EXPORTS_TRIE = 0x80000033


def commands(data):
    """(offset, cmd, cmdsize) of every load command of a 64-bit little-endian image."""
    ncmds = struct.unpack_from("<I", data, 16)[0]
    at = 32
    found = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, at)
        found.append((at, cmd, size))
        at += size
    return found


def command(data, wanted):
    return next((at, size) for at, cmd, size in commands(data) if cmd == wanted)


def put32(data, at, value):
    struct.pack_into("<I", data, at, value)


def section(data, segment, name):
    """(offset, size) of a section."""
    for at, cmd, _ in commands(data):
        if cmd != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from("<I", data, at + 64)[0]
        for index in range(nsects):
            base = at + 72 + index * 80
            sectname = data[base:base + 16].rstrip(b"\0").decode()
            segname = data[base + 16:base + 32].rstrip(b"\0").decode()
            if (segname, sectname) == (segment, name):
                size = struct.unpack_from("<Q", data, base + 40)[0]
                offset = struct.unpack_from("<I", data, base + 48)[0]
                return offset, size
    raise KeyError(name)


def signature_offset(data):
    at, _ = command(data, LC_CODE_SIGNATURE)
    return struct.unpack_from("<I", data, at + 8)[0]


def code_directory_offset(data):
    signature = signature_offset(data)
    count = struct.unpack_from(">I", data, signature + 8)[0]
    for index in range(count):
        slot, offset = struct.unpack_from(">II", data, signature + 12 + index * 8)
        if slot == 0:
            return signature + offset
    raise KeyError("CodeDirectory")


def edited(source, change):
    data = bytearray(source)
    change(data)
    return bytes(data)


def fat(slices, count=None, nested=False):
    """A universal file with 32-bit offsets: slices are (cputype, subtype, offset, size, align,
    bytes placed at offset)."""
    header = struct.pack(">II", 0xCAFEBABE, len(slices) if count is None else count)
    for cputype, subtype, offset, size, align, _ in slices:
        header += struct.pack(">IIIII", cputype, subtype, offset, size, align)
    end = max(offset + len(content) for _, _, offset, _, _, content in slices)
    data = bytearray(max(end, len(header)))
    data[:len(header)] = header
    for _, _, offset, _, _, content in slices:
        data[offset:offset + len(content)] = content
    return bytes(data)


def main():
    bin_dir, hostile = Path(sys.argv[1]), Path(sys.argv[2])
    hardened = (bin_dir / "hardened").read_bytes()
    library = (bin_dir / "library").read_bytes()

    def set_cryptid(data):
        at, _ = command(data, LC_ENCRYPTION_INFO_64)
        put32(data, at + 16, 1)

    (bin_dir / "encrypted").write_bytes(edited(hardened, set_cryptid))

    def flip_code(data):
        offset, _ = section(data, "__TEXT", "__text")
        data[offset + 16] ^= 0xFF

    (bin_dir / "tampered").write_bytes(edited(hardened, flip_code))
    plain = (bin_dir / "plain").read_bytes()
    flags = struct.unpack_from("<I", plain, 24)[0]
    (bin_dir / "stack-exec").write_bytes(edited(plain, lambda data: put32(data, 24, flags | 0x20000)))
    (bin_dir / "no-pie").write_bytes(edited(plain, lambda data: put32(data, 24, flags & ~0x200000)))

    def at_command(wanted, field, value):
        def change(data):
            at, _ = command(data, wanted)
            put32(data, at + field, value)
        return change

    size = len(hardened)
    arm64 = 0x0100000C
    cases = {
        "truncated-header": hardened[:20],
        "commands-past-end": edited(hardened, lambda data: put32(data, 20, size * 2)),
        "too-many-commands": edited(hardened, lambda data: put32(data, 16, 100000)),
        "command-size-zero": edited(hardened, at_command(LC_UUID, 4, 0)),
        "command-size-unaligned": edited(hardened, at_command(LC_UUID, 4, 28)),
        "dylib-name-outside": edited(hardened, at_command(LC_LOAD_DYLIB, 8, 0x1000)),
        "segment-outside": edited(hardened, lambda data: struct.pack_into(
            "<Q", data, command_named_segment(data, "__LINKEDIT") + 48, 1 << 40)),
        "symbols-outside": edited(hardened, at_command(LC_SYMTAB, 8, size)),
        "symbol-name-outside": edited(hardened, break_first_import_name),
        "signature-outside": edited(hardened, at_command(LC_CODE_SIGNATURE, 8, size)),
        "signature-not-superblob": edited(hardened, lambda data: struct.pack_into(
            ">I", data, signature_offset(data), 0x12345678)),
        "signature-count-huge": edited(hardened, lambda data: struct.pack_into(
            ">I", data, signature_offset(data) + 8, 0xFFFFFFFF)),
        "code-directory-hashes-outside": edited(hardened, lambda data: struct.pack_into(
            ">I", data, code_directory_offset(data) + 16, 0xFFFF)),
        "code-directory-slots-huge": edited(hardened, lambda data: struct.pack_into(
            ">I", data, code_directory_offset(data) + 28, 0x7FFFFFFF)),
        "duplicate-exports-trie": edited(hardened, at_command(LC_DATA_IN_CODE, 0,
                                                              LC_DYLD_EXPORTS_TRIE)),
        "rpath-unterminated": edited(library, unterminate_rpath),
        # MH_MAGIC_64 in big-endian byte order: the image claims to be big-endian.
        "big-endian": edited(hardened, lambda data: struct.pack_into(">I", data, 0, 0xFEEDFACF)),
        "universal-overlapping": fat([(arm64, 0, 4096, size, 12, hardened),
                                      (arm64, 2, 4096, size, 12, hardened)]),
        "universal-slice-outside": fat([(arm64, 0, 4096, size * 4, 12, hardened)]),
        "universal-nested": fat([(arm64, 0, 4096, 4096 + size, 12,
                                  fat([(arm64, 0, 4096, size, 12, hardened)]))]),
        "universal-java-like": struct.pack(">IIHH", 0xCAFEBABE, 61, 0, 52),
    }
    for name, data in cases.items():
        (hostile / name).write_bytes(data)


def command_named_segment(data, name):
    for at, cmd, _ in commands(data):
        if cmd == LC_SEGMENT_64 and data[at + 8:at + 24].rstrip(b"\0").decode() == name:
            return at
    raise KeyError(name)


def break_first_import_name(data):
    """Points the first undefined external symbol's name past the string table."""
    at, _ = command(data, LC_SYMTAB)
    symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, at + 8)
    for index in range(nsyms):
        entry = symoff + index * 16
        n_type = data[entry + 4]
        if n_type & 0xE0 == 0 and n_type & 0x0E == 0 and n_type & 1:
            put32(data, entry, strsize + 100)
            return
    raise KeyError("import")


def unterminate_rpath(data):
    """Fills LC_RPATH's string to the end of the command, without a NUL."""
    at, size = command(data, LC_RPATH)
    offset = struct.unpack_from("<I", data, at + 8)[0]
    data[at + offset:at + size] = b"A" * (size - offset)


if __name__ == "__main__":
    main()
