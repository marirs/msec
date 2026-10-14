#!/usr/bin/env python3
"""Writes small ELF shared libraries with chosen hardening properties, and an APK holding them.

Python standard library only, independent of msec. The libraries are not runnable: they carry
the headers, dynamic entries, symbol tables and sections the hardening checks read.

Usage: make_elf_fixtures.py <base.apk> <output directory>
"""

from __future__ import annotations

import io
import struct
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

PT_LOAD, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
DT = dict(NULL=0, NEEDED=1, HASH=4, STRTAB=5, SYMTAB=6, STRSZ=10, SYMENT=11, SONAME=14, RPATH=15, DEBUG=21,
          TEXTREL=22, BIND_NOW=24, RUNPATH=29, FLAGS=30, GNU_HASH=0x6FFFFEF5, FLAGS_1=0x6FFFFFFB)
SHT = dict(NULL=0, PROGBITS=1, SYMTAB=2, STRTAB=3, HASH=5, DYNAMIC=6, DYNSYM=11, GNU_HASH=0x6FFFFFF6)
ET_EXEC, ET_DYN = 2, 3
EM_ARM, EM_AARCH64 = 40, 183
STT_FUNC, STB_GLOBAL = 2, 1


@dataclass
class Library:
    name: str
    bits: int = 64
    machine: int = EM_AARCH64
    elf_type: int = ET_DYN
    align: int = 16384
    stack_flags: int | None = PF_R | PF_W
    relro: bool = True
    dynamic: list[tuple[str, int | str]] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    static_symbols: list[str] = field(default_factory=list)
    extra_sections: dict[str, bytes] = field(default_factory=dict)
    gnu_hash: bool = True
    section_headers: bool = True
    comment: str = "Android (11349228, +pgo, +bolt, +lto, -mlgo, based on r487747e) clang version 17.0.2"


class StringTable:
    def __init__(self) -> None:
        self.data = bytearray(b"\0")
        self.offsets: dict[str, int] = {"": 0}

    def add(self, text: str) -> int:
        if text not in self.offsets:
            self.offsets[text] = len(self.data)
            self.data += text.encode() + b"\0"
        return self.offsets[text]


def gnu_hash(name: str) -> int:
    h = 5381
    for byte in name.encode():
        h = (h * 33 + byte) & 0xFFFFFFFF
    return h


def build(lib: Library) -> bytes:
    is64 = lib.bits == 64
    word = "Q" if is64 else "I"
    ehsize, phentsize, shentsize, symsize = (64, 56, 64, 24) if is64 else (52, 32, 40, 16)
    dynstr = StringTable()
    symbols = [(name, False) for name in lib.imports] + [(name, True) for name in lib.exports]
    dynamic_entries: list[tuple[int, int]] = []
    for tag, value in lib.dynamic:
        dynamic_entries.append((DT[tag], dynstr.add(value) if isinstance(value, str) else value))
    for name, _ in symbols:
        dynstr.add(name)

    def symbol(name_offset: int, defined: bool) -> bytes:
        info = (STB_GLOBAL << 4) | STT_FUNC
        shndx = 7 if defined else 0
        if is64:
            return struct.pack("<IBBHQQ", name_offset, info, 0, shndx, 0, 0)
        return struct.pack("<IIIBBH", name_offset, 0, 0, info, 0, shndx)

    dynsym = bytes(symsize) + b"".join(symbol(dynstr.offsets[name], defined) for name, defined in symbols)
    if lib.gnu_hash:
        count = len(symbols)
        chains = [(gnu_hash(name) & ~1) | (1 if index == count - 1 else 0) for index, (name, _) in enumerate(symbols)]
        bloom = (b"\xff" * (8 if is64 else 4))
        hash_table = struct.pack("<IIII", 1, 1, 1, 6) + bloom + struct.pack("<I", 1 if count else 0)
        hash_table += b"".join(struct.pack("<I", chain) for chain in chains)
        hash_tag, hash_type, hash_name = "GNU_HASH", SHT["GNU_HASH"], ".gnu.hash"
    else:
        count = len(symbols) + 1
        hash_table = struct.pack("<II", 1, count) + struct.pack("<I", 0) + bytes(4 * count)
        hash_tag, hash_type, hash_name = "HASH", SHT["HASH"], ".hash"

    symtab_strings = StringTable()
    symtab = bytes(symsize) + b"".join(symbol(symtab_strings.add(name), True) for name in lib.static_symbols)

    # Layout: header, program headers, then blobs at 16-byte boundaries.
    program_count = 2 + (lib.stack_flags is not None) + lib.relro
    cursor = ehsize + phentsize * program_count
    blobs: list[tuple[str, int, bytes]] = []

    def place(name: str, kind: int, data: bytes) -> int:
        nonlocal cursor
        cursor = (cursor + 15) & ~15
        blobs.append((name, kind, bytes(data)))
        offset = cursor
        cursor += len(data)
        return offset

    dynsym_at = place(".dynsym", SHT["DYNSYM"], dynsym)
    dynstr_at = place(".dynstr", SHT["STRTAB"], dynstr.data)
    hash_at = place(hash_name, hash_type, hash_table)
    dynamic_entries += [(DT["STRTAB"], dynstr_at), (DT["SYMTAB"], dynsym_at), (DT["STRSZ"], len(dynstr.data)),
                        (DT["SYMENT"], symsize), (DT[hash_tag], hash_at), (DT["NULL"], 0)]
    dynamic = b"".join(struct.pack(f"<{'q' if is64 else 'i'}{word}", tag, value) for tag, value in dynamic_entries)
    dynamic_at = place(".dynamic", SHT["DYNAMIC"], dynamic)
    comment_at = place(".comment", SHT["PROGBITS"], lib.comment.encode() + b"\0")
    extra = [(name, place(name, SHT["PROGBITS"], data)) for name, data in lib.extra_sections.items()]
    if lib.static_symbols:
        symtab_at = place(".symtab", SHT["SYMTAB"], symtab)
        strtab_at = place(".strtab", SHT["STRTAB"], symtab_strings.data)
    shstrtab = StringTable()
    for name, _, _ in blobs:
        shstrtab.add(name)
    shstrtab.add(".shstrtab")
    shstrtab_at = place(".shstrtab", SHT["STRTAB"], shstrtab.data)
    section_offset = (cursor + 7) & ~7
    file_size = section_offset + (shentsize * (len(blobs) + 1) if lib.section_headers else 0)

    def program(kind: int, flags: int, offset: int, size: int, align: int) -> bytes:
        if is64:
            return struct.pack("<IIQQQQQQ", kind, flags, offset, offset, offset, size, size, align)
        return struct.pack("<IIIIIIII", kind, offset, offset, offset, size, size, flags, align)

    programs = [program(PT_LOAD, PF_R | PF_X | PF_W, 0, file_size, lib.align),
                program(PT_DYNAMIC, PF_R | PF_W, dynamic_at, len(dynamic), 8)]
    if lib.stack_flags is not None:
        programs.append(program(PT_GNU_STACK, lib.stack_flags, 0, 0, 16))
    if lib.relro:
        programs.append(program(PT_GNU_RELRO, PF_R, dynamic_at, len(dynamic), 1))

    names = {name: index + 1 for index, (name, _, _) in enumerate(blobs)}

    def section(name: str, kind: int, offset: int, size: int) -> bytes:
        link = 0
        if name == ".dynsym" or name == hash_name or name == ".dynamic":
            link = names[".dynstr"]
        if name == ".symtab":
            link = names[".strtab"]
        entsize = symsize if name in (".dynsym", ".symtab") else 0
        if is64:
            return struct.pack("<IIQQQQIIQQ", shstrtab.offsets[name], kind, 0, offset, offset, size, link, 0, 8, entsize)
        return struct.pack("<IIIIIIIIII", shstrtab.offsets[name], kind, 0, offset, offset, size, link, 0, 4, entsize)

    out = bytearray(file_size)
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1, 1, 0]) + bytes(8)
    section_count = len(blobs) + 1 if lib.section_headers else 0
    shstrndx = names[".shstrtab"] if lib.section_headers else 0
    if is64:
        header = ident + struct.pack("<HHIQQQIHHHHHH", lib.elf_type, lib.machine, 1, 0, ehsize,
                                     section_offset if lib.section_headers else 0, 0, ehsize, phentsize,
                                     program_count, shentsize, section_count, shstrndx)
    else:
        header = ident + struct.pack("<HHIIIIIHHHHHH", lib.elf_type, lib.machine, 1, 0, ehsize,
                                     section_offset if lib.section_headers else 0, 0x05000000, ehsize, phentsize,
                                     program_count, shentsize, section_count, shstrndx)
    out[:len(header)] = header
    out[ehsize:ehsize + phentsize * program_count] = b"".join(programs)
    for (name, kind, data), offset in zip(blobs, sorted(set(o for o in [dynsym_at, dynstr_at, hash_at, dynamic_at, comment_at, *[o for _, o in extra], *( [symtab_at, strtab_at] if lib.static_symbols else []), shstrtab_at]))):
        out[offset:offset + len(data)] = data
    if lib.section_headers:
        headers = bytes(shentsize)
        offsets = {}
        position = ehsize + phentsize * program_count
        for name, kind, data in blobs:
            position = (position + 15) & ~15
            offsets[name] = position
            position += len(data)
        headers += b"".join(section(name, kind, offsets[name], len(data)) for name, kind, data in blobs)
        out[section_offset:section_offset + len(headers)] = headers
    return bytes(out)


LIBRARIES = [
    Library("libhardened.so",
            dynamic=[("NEEDED", "libc.so"), ("SONAME", "libhardened.so"), ("FLAGS", 0x8), ("FLAGS_1", 0x1)],
            imports=["__stack_chk_fail", "__memcpy_chk", "__strlen_chk", "malloc"],
            exports=["Java_com_example_Native_run"]),
    Library("libweak.so", elf_type=ET_EXEC, align=4096, stack_flags=PF_R | PF_W | PF_X, relro=False,
            dynamic=[("NEEDED", "libc.so"), ("RPATH", "/data/local/tmp"), ("RUNPATH", "$ORIGIN/../plugins"),
                     ("TEXTREL", 0), ("FLAGS", 0x4)],
            imports=["strcpy", "sprintf"], exports=["entry"], static_symbols=["secret_key_check", "debug_dump"],
            extra_sections={".debug_info": b"\x01" * 64, ".debug_line": b"\x02" * 32}, gnu_hash=False,
            comment="GCC: (GNU) 4.9.x 20150123 (prerelease)"),
    Library("libpartial.so", bits=32, machine=EM_ARM, align=4096,
            dynamic=[("NEEDED", "libc.so"), ("DEBUG", 0)],
            imports=["__stack_chk_fail", "memcpy"], exports=["JNI_OnLoad"]),
    Library("libapp.so", relro=False, dynamic=[("SONAME", "libapp.so")],
            exports=["_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotData"]),
    Library("libnosections.so", section_headers=False,
            dynamic=[("NEEDED", "libc.so"), ("FLAGS", 0x8)],
            imports=["__stack_chk_fail", "__read_chk"], exports=["hidden_entry"]),
]


def aligned_info(name: str, offset: int, alignment: int) -> zipfile.ZipInfo:
    """A stored entry whose data starts at a multiple of `alignment` (padding in the extra field),
    or deliberately one byte past it when `alignment` is negative."""
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    header = 30 + len(name.encode())
    target = abs(alignment)
    padding = (-(offset + header + 4)) % target
    if alignment < 0:
        padding += 1
    info.extra = struct.pack("<HH", 0xD935, padding) + bytes(padding)
    return info


def main() -> None:
    base = zipfile.ZipFile(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    built = {lib.name: build(lib) for lib in LIBRARIES}
    for name, data in built.items():
        (out_dir / name).write_bytes(data)
    placement = [
        ("lib/arm64-v8a/libhardened.so", 16384),
        ("lib/arm64-v8a/libweak.so", -16384),
        ("lib/armeabi-v7a/libpartial.so", None),
        ("lib/arm64-v8a/libapp.so", 16384),
        ("lib/arm64-v8a/libnosections.so", None),
    ]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as apk:
        for info in base.infolist():
            apk.writestr(info, base.read(info))
        for path, alignment in placement:
            data = built[path.rsplit("/", 1)[1]]
            if alignment is None:
                apk.writestr(zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)
            else:
                apk.writestr(aligned_info(path, buffer.tell(), alignment), data)
    (out_dir / "native.apk").write_bytes(buffer.getvalue())


if __name__ == "__main__":
    main()
