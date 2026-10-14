#!/usr/bin/env python3
"""Synthetic DEX files for msec's DEX reader, written from scratch (no third-party input).

    python3 -I make_dex_fixtures.py <v035.dex> <out-dir>

Writes:

- ``container.dex``: a version 041 container holding two logical DEX files, which d8 only
  produces for apps past the 64K method limit.
- ``hostile/*.dex``: files that each break exactly one rule. The synthetic ones carry a correct
  checksum and signature, so the named problem is the only one; the rest are byte edits of the
  d8-built ``v035.dex``.

The synthetic layout is header, string_ids, type_ids, class_defs, then the data section
(string_data items, type_lists, any extra bytes, map_list). There are no protos, fields,
methods or code: a class without class data is valid, and the inventory needs nothing more.
"""

import hashlib
import struct
import sys
import zlib
from pathlib import Path

NO_INDEX = 0xFFFFFFFF
ENDIAN_CONSTANT = 0x12345678
ACC_PUBLIC = 0x1
TYPE_HEADER_ITEM = 0x0000
TYPE_STRING_ID_ITEM = 0x0001
TYPE_TYPE_ID_ITEM = 0x0002
TYPE_CLASS_DEF_ITEM = 0x0006
TYPE_MAP_LIST = 0x1000
TYPE_TYPE_LIST = 0x1001
TYPE_STRING_DATA_ITEM = 0x2002


def uleb128(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def string_data(text):
    """A string_data_item: UTF-16 length, then MUTF-8 (each UTF-16 unit encoded on its own,
    U+0000 as C0 80), then a zero byte."""
    units = [unit for (unit,) in struct.iter_unpack("<H", text.encode("utf-16-le", "surrogatepass"))]
    data = bytearray()
    for unit in units:
        if 0 < unit < 0x80:
            data.append(unit)
        elif unit < 0x800:
            data += bytes([0xC0 | unit >> 6, 0x80 | unit & 0x3F])
        else:
            data += bytes([0xE0 | unit >> 12, 0x80 | (unit >> 6) & 0x3F, 0x80 | unit & 0x3F])
    return uleb128(len(units)) + bytes(data) + b"\0"


def pad4(buffer):
    buffer += b"\0" * (-len(buffer) % 4)


class Layout:
    """Where one logical DEX file put its tables, as absolute offsets."""


def section(version, strings, types, classes, type_lists=(), extra=b"", base=0, string_targets=None):
    """One logical DEX file starting at ``base`` in its container.

    ``strings`` are texts or raw string_data bytes; ``string_targets`` (default: one id per
    string) lists which string each string_id points to. ``classes`` are
    ``(class_type, superclass_type, type_list_index or None)``.
    """
    header_size = 0x78 if version >= 41 else 0x70
    targets = list(range(len(strings))) if string_targets is None else string_targets
    layout = Layout()
    layout.string_ids = base + header_size if targets else 0
    layout.type_ids = base + header_size + 4 * len(targets) if types else 0
    layout.class_defs = base + header_size + 4 * len(targets) + 4 * len(types) if classes else 0
    data_start = header_size + 4 * len(targets) + 4 * len(types) + 32 * len(classes)
    data = bytearray()
    string_offsets = []
    for text in strings:
        string_offsets.append(base + data_start + len(data))
        data += text if isinstance(text, bytes) else string_data(text)
    pad4(data)
    list_offsets = []
    for type_list in type_lists:
        list_offsets.append(base + data_start + len(data))
        data += struct.pack("<I", len(type_list)) + b"".join(struct.pack("<H", t) for t in type_list)
        pad4(data)
    layout.extra = base + data_start + len(data)
    data += extra
    pad4(data)
    layout.map = base + data_start + len(data)
    items = [(TYPE_HEADER_ITEM, 1, base)]
    items += [(TYPE_STRING_ID_ITEM, len(targets), layout.string_ids)] if targets else []
    items += [(TYPE_TYPE_ID_ITEM, len(types), layout.type_ids)] if types else []
    items += [(TYPE_CLASS_DEF_ITEM, len(classes), layout.class_defs)] if classes else []
    items += [(TYPE_STRING_DATA_ITEM, len(strings), string_offsets[0])] if strings else []
    items += [(TYPE_TYPE_LIST, len(type_lists), list_offsets[0])] if type_lists else []
    items += [(TYPE_MAP_LIST, 1, layout.map)]
    data += struct.pack("<I", len(items))
    for kind, size, offset in items:
        data += struct.pack("<HHII", kind, 0, size, offset)
    layout.items = items
    file_size = data_start + len(data)

    body = bytearray()
    body += b"".join(struct.pack("<I", string_offsets[target]) for target in targets)
    body += b"".join(struct.pack("<I", descriptor) for descriptor in types)
    for class_type, superclass, interfaces in classes:
        interfaces_offset = 0 if interfaces is None else list_offsets[interfaces]
        body += struct.pack("<8I", class_type, ACC_PUBLIC, superclass, interfaces_offset,
                            NO_INDEX, 0, 0, 0)
    data_size, data_offset = (0, 0) if version >= 41 else (len(data), base + data_start)
    header = bytearray(b"dex\n%03d\0" % version)
    header += b"\0" * 24  # checksum and signature, filled in by seal()
    header += struct.pack(
        "<20I", file_size, header_size, ENDIAN_CONSTANT, 0, 0, layout.map,
        len(targets), layout.string_ids, len(types), layout.type_ids, 0, 0, 0, 0, 0, 0,
        len(classes), layout.class_defs, data_size, data_offset,
    )
    if version >= 41:
        header += struct.pack("<II", 0, base)  # container_size, set by seal(); header_offset
    return bytearray(header + body + data), layout


def seal(container, header_offsets):
    """Sets each header's container size (version 041), then its checksum and signature."""
    for offset in header_offsets:
        file_size, header_size = struct.unpack_from("<II", container, offset + 32)
        if header_size == 0x78:
            struct.pack_into("<I", container, offset + 0x70, len(container))
        end = offset + file_size
        container[offset + 12 : offset + 32] = hashlib.sha1(container[offset + 32 : end]).digest()
        struct.pack_into("<I", container, offset + 8, zlib.adler32(container[offset + 12 : end]))
    return bytes(container)


def single(*args, patch=None, **kwargs):
    dex, layout = section(*args, **kwargs)
    if patch:
        patch(dex, layout)
    return seal(dex, [0])


def container():
    first, _ = section(41, ["LA;", "LB;", "Ljava/lang/Object;"], [0, 1, 2], [(0, 2, None), (1, 0, None)])
    pad4(first)
    second, _ = section(41, ["LC;", "Ljava/lang/Object;"], [0, 1], [(0, 1, None)], base=len(first))
    return seal(first + second, [0, len(first)])


def container_table_in_later_section():
    """``container.dex`` with the first file's class_defs pointing at the second file's table, so
    two logical files would share (and a hostile container could multiply) one table."""
    dex = bytearray(container())
    second = struct.unpack_from("<I", dex, 32)[0]
    second_class_defs = struct.unpack_from("<I", dex, second + 100)[0]
    struct.pack_into("<II", dex, 96, 1, second_class_defs)
    return seal(dex, [0])


def classes_with(problem):
    """Two classes, ``LA;`` and ``LB;``, with one rule broken."""
    strings = ["LA;", "LB;", "Ljava/lang/Object;", "Ljava/lang/Runnable;"]
    types = [0, 1, 2, 3]
    classes = [(0, 2, None), (1, 2, 0)]
    type_lists = [[3]]
    patch = None
    if problem == "duplicate-class":
        classes = [(0, 2, None), (0, 2, None)]
    elif problem == "bad-class-index":
        classes = [(0, 2, None), (9, 2, None)]
    elif problem == "bad-superclass-index":
        classes = [(0, 2, None), (1, 9, None)]
    elif problem == "bad-descriptor-index":
        types = [0, 1, 2, 9]
    elif problem == "bad-interfaces-offset":
        def patch(dex, layout):
            struct.pack_into("<I", dex, layout.class_defs + 32 + 12, 0x7FFF_FFF0)
    elif problem == "unsorted-strings":
        strings = ["LB;", "LA;", "Ljava/lang/Object;", "Ljava/lang/Runnable;"]
    elif problem == "map-out-of-order":
        def patch(dex, layout):
            # Swap the type_ids and class_defs entries.
            first = layout.map + 4 + 12 * 2
            second = layout.map + 4 + 12 * 3
            dex[first : first + 12], dex[second : second + 12] = dex[second : second + 12], dex[first : first + 12]
    elif problem == "map-out-of-bounds":
        def patch(dex, layout):
            struct.pack_into("<I", dex, 52, len(dex) + 64)
    return single(35, strings, types, classes, type_lists=type_lists, patch=patch)


def invalid_mutf8():
    # A four-byte UTF-8 sequence (U+1F600): standard UTF-8, but not MUTF-8, which encodes the two
    # surrogates separately.
    return single(35, ["LA;", bytes([2, 0xF0, 0x9F, 0x98, 0x80, 0])], [0], [])


def string_amplification():
    # 8,000 string ids all pointing to one 30,000-character string: 240 MB of decoding from a
    # 62 KB file unless the reader bounds the total.
    return single(35, ["a" * 30_000], [], [], string_targets=[0] * 8_000)


def type_list_amplification():
    # 2,000 classes whose interface lists overlap in a 32 KB region of words that each read as a
    # list of 8,192 entries: 16 million entries from a 96 KB file unless the reader bounds them.
    region = struct.pack("<I", 0x2000) * 0x2000

    def patch(dex, layout):
        for index in range(2_000):
            struct.pack_into("<I", dex, layout.class_defs + 32 * index + 12, layout.extra + 4 * index)

    return single(35, ["LA;", "Ljava/lang/Object;"], [0, 1], [(0, 1, None)] * 2_000, extra=region, patch=patch)


def edited(d8_dex, problem):
    """``v035.dex`` with one edit. The checksum and signature are recomputed unless the edit is
    about them, or leaves nothing to recompute them over."""
    dex = bytearray(d8_dex)
    if problem == "bad-checksum":
        dex[8] ^= 0xFF
    elif problem == "bad-signature":
        dex[12] ^= 0xFF
        struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]))
    elif problem == "version-036":
        dex[4:8] = b"036\0"
    elif problem == "compact-dex":
        dex[0:8] = b"cdex001\0"
    elif problem == "byte-swapped":
        struct.pack_into(">I", dex, 40, ENDIAN_CONSTANT)
    elif problem == "bad-header-size":
        struct.pack_into("<I", dex, 36, 0x78)
    elif problem == "truncated":
        del dex[len(dex) // 2 :]
    elif problem == "trailing-data":
        dex += b"\0" * 16
    elif problem == "string-ids-out-of-bounds":
        struct.pack_into("<I", dex, 60, len(dex))
    elif problem == "method-ids-out-of-bounds":
        struct.pack_into("<I", dex, 92, len(dex))
    if problem not in ("bad-checksum", "bad-signature", "compact-dex", "truncated", "trailing-data"):
        # Re-sign, so the edit is the file's only problem.
        dex[12:32] = hashlib.sha1(dex[32:]).digest()
        struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]))
    return bytes(dex)


def main():
    d8_dex = Path(sys.argv[1]).read_bytes()
    out = Path(sys.argv[2])
    (out / "hostile").mkdir(parents=True, exist_ok=True)
    (out / "container.dex").write_bytes(container())
    files = {problem: classes_with(problem) for problem in (
        "duplicate-class", "bad-class-index", "bad-superclass-index", "bad-descriptor-index",
        "bad-interfaces-offset", "unsorted-strings", "map-out-of-order", "map-out-of-bounds",
    )}
    files["container-table-in-later-section"] = container_table_in_later_section()
    files["invalid-mutf8"] = invalid_mutf8()
    files["string-amplification"] = string_amplification()
    files["type-list-amplification"] = type_list_amplification()
    for problem in ("bad-checksum", "bad-signature", "version-036", "compact-dex", "byte-swapped",
                    "bad-header-size", "truncated", "trailing-data", "string-ids-out-of-bounds",
                    "method-ids-out-of-bounds"):
        files[problem] = edited(d8_dex, problem)
    for name, data in files.items():
        (out / "hostile" / f"{name}.dex").write_bytes(data)


if __name__ == "__main__":
    main()
