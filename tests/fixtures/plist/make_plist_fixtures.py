"""Writes msec's plist fixtures: XML sources (xml/) and crafted binary plists (binary/).

    python3 -I make_plist_fixtures.py <out-dir>

Each file probes one rule of Core Foundation's plist readers; build_plist.sh then records
plutil's verdict on every file and, for those it reads, the XML it writes, which the tests in
tests/plist.rs compare msec against. The valid XML sources are also converted to binary by
plutil (as Xcode writes Info.plist), so both formats of the same content are checked.
"""

import struct
import sys
from pathlib import Path


def bplist(objects, top=0, reference_size=1, offset_size=None, version=b"00", trailer=None,
           suffix=b""):
    """A binary plist from encoded objects (references already encoded by the caller)."""
    body = b"bplist" + version
    offsets = []
    for encoded in objects:
        offsets.append(len(body))
        body += encoded
    table = len(body)
    offset_size = offset_size or max(1, (max(offsets).bit_length() + 7) // 8)
    for offset in offsets:
        body += offset.to_bytes(offset_size, "big")
    fields = trailer or (offset_size, reference_size, len(objects), top, table)
    return body + b"\0" * 6 + struct.pack(">BBQQQ", *fields) + suffix


def ref(index, size=1):
    return index.to_bytes(size, "big")


def ascii_string(text):
    raw = text.encode("latin-1")
    assert len(raw) < 15
    return bytes([0x50 | len(raw)]) + raw


def utf16_string(text):
    raw = text.encode("utf-16-be")
    return bytes([0x60 | (len(raw) // 2)]) + raw


def int8(value):
    return bytes([0x10, value])


def array(items, size=1):
    return bytes([0xA0 | len(items)]) + b"".join(ref(item, size) for item in items)


def dictionary(keys, values, size=1):
    return (bytes([0xD0 | len(keys)]) + b"".join(ref(key, size) for key in keys)
            + b"".join(ref(value, size) for value in values))


def nested_arrays(levels, leaf):
    """`levels` arrays, each holding the next, the innermost holding `leaf` (or nothing)."""
    objects = [array([index + 1], size=2) for index in range(levels - 1)]
    if leaf is None:
        objects.append(bytes([0xA0]))
    else:
        objects.append(array([levels], size=2))
        objects.append(leaf)
    return bplist(objects, reference_size=2)


def expansion_bomb(levels):
    """Each array holds the next twice: 2^levels leaves from a few hundred bytes. Core
    Foundation shares the objects; a reader that copies them must stop."""
    objects = [array([index + 1, index + 1]) for index in range(levels)] + [int8(1)]
    return bplist(objects)


BINARY = {
    # Rules Core Foundation applies to the header and trailer.
    "version-0x.bplist": bplist([int8(1)], version=b"0x"),
    "version-10.bplist": bplist([int8(1)], version=b"10"),
    "trailing-byte.bplist": bplist([int8(1)], suffix=b"\0"),
    "offset-size-3.bplist": bplist([int8(1)], offset_size=3),
    "offset-size-9.bplist": bplist([int8(1)], trailer=(9, 1, 1, 0, 10)),
    "reference-size-0.bplist": bplist([int8(1)], trailer=(1, 0, 1, 0, 10)),
    "no-objects.bplist": bplist([int8(1)], trailer=(1, 1, 0, 0, 10)),
    "top-out-of-range.bplist": bplist([int8(1)], trailer=(1, 1, 1, 1, 10)),
    "table-in-header.bplist": bplist([int8(1)], trailer=(1, 1, 1, 0, 4)),
    "count-overflow.bplist": bplist([int8(1)], trailer=(8, 1, 2**62, 0, 10)),
    "references-too-small.bplist": bplist([array([1, 2])] + [int8(1)] * 300,
                                          reference_size=1),
    "offset-in-header.bplist": b"bplist00" + int8(1) + bytes([6]) + b"\0" * 6
    + struct.pack(">BBQQQ", 1, 1, 1, 0, 10),
    "offset-in-table.bplist": b"bplist00" + int8(1) + bytes([10]) + b"\0" * 6
    + struct.pack(">BBQQQ", 1, 1, 1, 0, 10),
    "object-past-area.bplist": b"bplist00" + b"\x13\x01" + bytes([8]) + b"\0" * 6
    + struct.pack(">BBQQQ", 1, 1, 1, 0, 10),
    "gap-between-objects.bplist": b"bplist00" + int8(1) + b"junk" + bytes([8]) + b"\0" * 6
    + struct.pack(">BBQQQ", 1, 1, 1, 0, 14),
    "shared-offset.bplist": b"bplist00" + b"\xa2\x01\x02" + int8(5) + bytes([8, 11, 11])
    + b"\0" * 6 + struct.pack(">BBQQQ", 1, 1, 3, 0, 13),
    "reference-out-of-range.bplist": bplist([array([5]), int8(1)]),
    # Objects.
    "null.bplist": bplist([array([1]), b"\x00"]),
    "fill.bplist": bplist([array([1]), b"\x0f"]),
    "url-marker.bplist": bplist([array([1]), b"\x0c"]),
    "set.bplist": bplist([bytes([0xC1, 1]), int8(1)]),
    "ordered-set.bplist": bplist([bytes([0xB1, 1]), int8(1)]),
    "utf8-string-marker.bplist": bplist([bytes([0x72]) + b"hi"]),
    "uid.bplist": bplist([array([1, 2]), bytes([0x80, 7]), bytes([0x8F]) + b"\0" * 15 + b"\x09"]),
    "integers.bplist": bplist([array([1, 2, 3, 4, 5, 6]), bytes([0x12, 0xFF, 0xFF, 0xFF, 0xFF]),
                               bytes([0x13]) + b"\xff" * 8, bytes([0x14]) + (5).to_bytes(16, "big"),
                               bytes([0x11, 0xFF, 0xFE]), int8(200),
                               bytes([0x13]) + (2**63 - 1).to_bytes(8, "big")]),
    "integer-128-wide.bplist": bplist([bytes([0x14]) + (2**64 + 5).to_bytes(16, "big")]),
    "integer-128-negative.bplist": bplist([bytes([0x14]) + ((-5) % 2**128).to_bytes(16, "big")]),
    "integer-32-bytes.bplist": bplist([bytes([0x15]) + b"\0" * 31 + b"\1"]),
    "real-2-bytes.bplist": bplist([bytes([0x21, 0x3C, 0])]),
    "reals.bplist": bplist([array([1, 2]), bytes([0x22]) + struct.pack(">f", 1.5),
                            bytes([0x23]) + struct.pack(">d", 3.14)]),
    "date.bplist": bplist([bytes([0x33]) + struct.pack(">d", 789_012_345.0)]),
    "date-marker-34.bplist": bplist([bytes([0x34]) + struct.pack(">d", 1.5)]),
    "latin1-ascii-string.bplist": bplist([bytes([0x52]) + b"\xc3\xa9"]),
    "nul-in-string.bplist": bplist([bytes([0x53]) + b"a\0b"]),
    "lone-surrogate.bplist": bplist([bytes([0x61]) + b"\xd8\x00"]),
    "extended-count.bplist": bplist([bytes([0x5F, 0x10, 3]) + b"abc"]),
    "extended-count-16.bplist": bplist([bytes([0x5F, 0x14]) + b"\0" * 15 + b"\x03abc"]),
    "extended-count-not-integer.bplist": bplist([bytes([0x5F, 0x20, 3]) + b"abc"]),
    "extended-count-huge.bplist": bplist([bytes([0x5F, 0x13]) + b"\x7f" + b"\xff" * 7 + b"abc"]),
    "top-level-string.bplist": bplist([ascii_string("hello")]),
    # Containers.
    "cycle.bplist": bplist([array([1]), array([0])]),
    "dictionary-contains-itself.bplist": bplist([dictionary([1], [0]), ascii_string("k")]),
    "integer-key.bplist": bplist([dictionary([1], [2]), int8(5), int8(6)]),
    "duplicate-key.bplist": bplist([dictionary([1, 1], [2, 3]), ascii_string("a"), int8(1),
                                    int8(2)]),
    "duplicate-key-two-encodings.bplist": bplist([dictionary([1, 2], [3, 4]), ascii_string("a"),
                                                  utf16_string("a"), int8(1), int8(2)]),
    "shared-objects.bplist": bplist([array([1, 1]), array([2, 2]), ascii_string("x")]),
    "depth-512-and-integer.bplist": nested_arrays(512, int8(1)),
    "depth-513-and-integer.bplist": nested_arrays(513, int8(1)),
    "depth-513-empty.bplist": nested_arrays(513, None),
    "expansion-bomb.bplist": expansion_bomb(40),
    "array-count-past-area.bplist": bplist([bytes([0xAF, 0x11, 0x10, 0x00]) + b"\x00"]),
}

XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>\n'
DOCTYPE = ('<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
           '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n')


def document(body):
    return XML_DECLARATION + DOCTYPE + '<plist version="1.0">\n' + body + "\n</plist>\n"


def nested_xml(levels, leaf=""):
    return "<plist>" + "<array>" * levels + leaf + "</array>" * levels + "</plist>"


INFO_PLIST = document("""<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>Fixture &amp; Co</string>
	<key>CFBundleExecutable</key>
	<string>Fixture</string>
	<key>CFBundleIdentifier</key>
	<string>dev.appchk.fixture</string>
	<key>CFBundleName</key>
	<string>Fixture</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>2.1</string>
	<key>CFBundleSupportedPlatforms</key>
	<array>
		<string>iPhoneOS</string>
	</array>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLName</key>
			<string>dev.appchk.fixture</string>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>fixture</string>
			</array>
		</dict>
	</array>
	<key>CFBundleVersion</key>
	<string>42</string>
	<key>DTPlatformName</key>
	<string>iphoneos</string>
	<key>DTSDKName</key>
	<string>iphoneos27.1</string>
	<key>DTXcode</key>
	<string>2710</string>
	<key>ITSAppUsesNonExemptEncryption</key>
	<false/>
	<key>LSApplicationQueriesSchemes</key>
	<array>
		<string>whatsapp</string>
	</array>
	<key>MinimumOSVersion</key>
	<string>17.0</string>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSExceptionDomains</key>
		<dict>
			<key>example.com</key>
			<dict>
				<key>NSExceptionMinimumTLSVersion</key>
				<string>TLSv1.0</string>
				<key>NSIncludesSubdomains</key>
				<true/>
			</dict>
		</dict>
	</dict>
	<key>NSCameraUsageDescription</key>
	<string>Scans documents.</string>
	<key>UIBackgroundModes</key>
	<array>
		<string>location</string>
	</array>
	<key>UIDeviceFamily</key>
	<array>
		<integer>1</integer>
		<integer>2</integer>
	</array>
	<key>UIRequiredDeviceCapabilities</key>
	<array>
		<string>arm64</string>
	</array>
</dict>""")

TYPES = document("""<dict>
	<key>strings</key>
	<array>
		<string>x &amp; &lt;y&gt; "q" 'a' é 😀</string>
		<string></string>
		<string/>
		<string>  spaces kept  </string>
		<string><![CDATA[a<b>&c]]>d</string>
		<string>&#65;&#x42;&#x1F600;&quot;&apos;</string>
		<key>a key outside a dictionary is a string</key>
	</array>
	<key>integers</key>
	<array>
		<integer>0</integer>
		<integer>-1</integer>
		<integer>9223372036854775807</integer>
		<integer>-9223372036854775808</integer>
		<integer>18446744073709551615</integer>
		<integer>0x10</integer>
		<integer>-0x10</integer>
		<integer>+ 7</integer>
		<integer>
		5</integer>
	</array>
	<key>reals</key>
	<array>
		<real>3.14</real>
		<real>1</real>
		<real>1e300</real>
		<real>5e-324</real>
		<real>-0</real>
		<real>inf</real>
		<real>-infinity</real>
		<real>NaN</real>
		<real>.5</real>
		<real> 1E5</real>
		<real>123.456</real>
		<real>1e-400</real>
	</array>
	<key>booleans</key>
	<array>
		<true/>
		<false></false>
		<true />
	</array>
	<key>dates</key>
	<array>
		<date>2001-01-01T00:00:00Z</date>
		<date>1970-01-01T00:00:00Z</date>
		<date>2026-13-02T03:04:05Z</date>
		<date>2025-02-29T25:04:05Z</date>
		<date>0000-01-01T00:00:00Z</date>
		<date>-001-01-01T00:00:00Z</date>
		<date>12026-01-02T03:04:05Z</date>
	</array>
	<key>data</key>
	<array>
		<data>AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw==</data>
		<data></data>
		<data> AA EC
		Aw== </data>
		<data>AA==AAEC</data>
		<data>AAE</data>
		<data>!!!!</data>
	</array>
	<key>deep data</key>
	<array><array><array><array><array><array><array><array><array><array><array>
		<data>QUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJDQUJD</data>
	</array></array></array></array></array></array></array></array></array></array></array>
	<key>empty</key>
	<array>
		<array/>
		<array></array>
		<dict/>
		<dict></dict>
	</array>
	<!-- a comment between a key and its value -->
	<key>sorted keys</key>
	<dict>
		<key>b</key><true/>
		<key>B</key><true/>
		<key>a</key><true/>
		<key>é</key><true/>
		<key>😀</key><true/>
		<key>Ａ</key><true/>
		<key>_</key><true/>
		<key>10</key><true/>
		<key>9</key><true/>
		<key></key><true/>
		<key>a&amp;b</key><true/>
		<key><![CDATA[c]]></key><true/>
	</dict>
	<?processing instruction?>
	<key>uid-shaped</key>
	<dict>
		<key>CF$UID</key>
		<integer>3</integer>
	</dict>
</dict>""")

XML = {
    "info.xml": INFO_PLIST,
    "types.xml": TYPES,
    # Document structure.
    "no-plist-element.xml": "<dict><key>a</key><integer>1</integer></dict>",
    "attributes-ignored.xml": '<plist version="9.9" foo="bar"><string a="b">x</string></plist>',
    "doctype-without-subset.xml": "<!DOCTYPE foo bar baz><plist><string>x</string></plist>",
    "doctype-internal-subset.xml": '<?xml version="1.0"?>\n<!DOCTYPE plist [ <!ENTITY e "boom"> ]>\n'
    "<plist><string>x</string></plist>",
    "entity-expansion.xml": '<?xml version="1.0"?>\n<!DOCTYPE plist [ <!ENTITY a "aaaaaaaaaa">'
    ' <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"> ]>\n<plist><string>&b;</string></plist>',
    "whitespace-before-root.xml": "  \n <plist> <string>x</string> </plist>",
    "trailing-content.xml": "<plist><string>x</string></plist>junk",
    "comments-and-instructions.xml": '<?xml version="1.0"?><!-- c --><plist><dict><?pi x?>'
    "<!-- d --><key>a</key><!-- e --><string>x</string></dict></plist>",
    "empty-plist.xml": "<plist></plist>",
    "self-closed-plist.xml": "<plist/>",
    "two-roots.xml": "<plist><string>x</string><string>y</string></plist>",
    "text-in-plist.xml": "<plist>junk<string>x</string></plist>",
    "unknown-tag.xml": "<plist><foo/></plist>",
    "upper-case-tag.xml": "<plist><String>x</String></plist>",
    "prefixed-tag.xml": "<plist><a:string>x</a:string></plist>",
    "quote-in-attribute.xml": '<plist version="a>b"><string>x</string></plist>',
    "unclosed.xml": "<plist><string>x</plist>",
    "mismatched-close.xml": "<plist><string>x</str></plist>",
    "close-tag-whitespace.xml": "<plist><string>x</string ></plist >",
    # Text.
    "comment-in-string.xml": "<plist><string>x<!-- mid -->y</string></plist>",
    "element-in-string.xml": "<plist><string><string>x</string></string></plist>",
    "less-than-in-text.xml": "<plist><string>a < b</string></plist>",
    "bare-ampersand.xml": "<plist><string>a & b</string></plist>",
    "unknown-entity.xml": "<plist><string>&nbsp;</string></plist>",
    "character-reference-zero.xml": "<plist><string>&#0;</string></plist>",
    "character-reference-surrogate.xml": "<plist><string>&#xD800;</string></plist>",
    "character-reference-too-large.xml": "<plist><string>&#x110000;</string></plist>",
    # Values.
    "integer-overflow.xml": "<plist><integer>18446744073709551616</integer></plist>",
    "integer-underflow.xml": "<plist><integer>-9223372036854775809</integer></plist>",
    "integer-trailing-space.xml": "<plist><integer>7 </integer></plist>",
    "integer-hex-digit.xml": "<plist><integer>1e3</integer></plist>",
    "integer-incomplete.xml": "<plist><integer>0x</integer></plist>",
    "integer-empty.xml": "<plist><integer></integer></plist>",
    "integer-self-closed.xml": "<plist><integer/></plist>",
    "real-hex.xml": "<plist><real>0x1p3</real></plist>",
    "real-trailing.xml": "<plist><real>1.5x</real></plist>",
    "real-signed-nan.xml": "<plist><real>+nan</real></plist>",
    "real-empty.xml": "<plist><real></real></plist>",
    "date-fraction.xml": "<plist><date>2026-01-02T03:04:05.75Z</date></plist>",
    "date-offset.xml": "<plist><date>2026-01-02T03:04:05+01:00</date></plist>",
    "date-one-digit-month.xml": "<plist><date>2026-1-02T03:04:05Z</date></plist>",
    "date-empty.xml": "<plist><date></date></plist>",
    "data-self-closed.xml": "<plist><data/></plist>",
    "true-with-text.xml": "<plist><true>x</true></plist>",
    "dictionary-odd.xml": "<plist><dict><key>a</key></dict></plist>",
    "dictionary-value-without-key.xml": "<plist><dict><string>a</string></dict></plist>",
    "duplicate-key.xml": "<plist><dict><key>a</key><integer>1</integer><key>a</key>"
    "<integer>2</integer></dict></plist>",
    "depth-511.xml": nested_xml(511, "<string>a</string>"),
    "depth-512.xml": nested_xml(512),
    # Encodings.
    "byte-order-mark.xml": "﻿<plist><string>x</string></plist>",
    "invalid-utf8.xml": None,
    "latin1.xml": None,
    "utf16.xml": None,
    "shift-jis.xml": None,
    "openstep.xml": '{ a = "b"; }',
}


def strings_depth(levels):
    """A .strings entry whose value nests `levels` arrays (the file's dictionary is level 1)."""
    return '"k" = ' + "(" * levels + ")" * levels + ";"


# Old-style OpenStep text and .strings files, one rule of Core Foundation's reader per file.
OPENSTEP = {
    # A realistic InfoPlist.strings, as other toolchains than Xcode ship it.
    "info-plist-strings.strings": '/* Localized versions of Info.plist keys */\n'
    '"CFBundleDisplayName" = "Fixture";\n'
    '"NSCameraUsageDescription" = "Scans the documents you choose.";\n',
    "comments.strings": '/* block */ "a" /* inside */ = /* inside */ "b" // line\n;\n// end',
    "comment-only.strings": "/* only a comment */\n",
    "whitespace-only.strings": "   \n\t \u2028 ",
    "unterminated-comment.strings": '"a" = "b";\n/* never closed',
    "unquoted.strings": "a.b-c/d:e$f_g = v1;\nkey=value;\n1 = 2;",
    "unquoted-plus.strings": "a+b = v;",
    "unquoted-non-ascii.strings": "ключ = v;",
    "quoted-non-ascii.strings": '"ключ" = "значение";',
    "single-quotes.strings": "'a' = 'b \"c\"';",
    "key-only.strings": '"a";\n"b" = "c";',
    "key-only-last.strings": '"a"',
    "duplicate-key.strings": '"a" = "first";\n"a" = "second";',
    "missing-semicolon.strings": '"a" = "b"',
    "missing-equals.strings": '"a" "b";',
    "missing-value.strings": "a = ;",
    "missing-key.strings": '= "v";',
    "leading-semicolon.strings": ';"a" = "b";',
    "double-semicolon.strings": '"a" = "b";;',
    "trailing-word.strings": '"a" = "b"; trailing',
    "concatenated-strings.strings": '"a" = "b" "c";',
    "unterminated-string.strings": '"a" = "b;',
    "escapes.strings": '"a" = "\\a\\b\\f\\n\\r\\t\\v\\"\\\'\\\\\\q\\x41\\u00e9";',
    "escaped-newline.strings": '"a" = "x\\\ny";',
    "raw-newline.strings": '"a" = "line1\nline2";',
    "octal.strings": '"a" = "\\101\\0101\\1\\12x\\200\\375";',
    "octal-all.strings": '"a" = "' + "".join("\\%o" % byte for byte in range(0x80, 0xFE)) + '";',
    "octal-376.strings": '"a" = "\\376";',
    "octal-377.strings": '"a" = "\\377";',
    "octal-wraps.strings": '"a" = "\\777";',
    "unicode-escapes.strings": '"a" = "\\U00e9\\U4\\U00410\\UD83D\\UDE00";',
    "unicode-escape-empty.strings": '"a" = "\\Uzz";',
    "unicode-lone-surrogate.strings": '"a" = "\\UD83D";',
    "arrays.strings": '"a" = (x, "y", (z), );\n"b" = ();',
    "array-missing-comma.strings": '"a" = ("x" "y");',
    "dictionaries.strings": '"a" = { b = c; "d" = { e = (f); }; };\n"g" = {};',
    "dictionary-missing-semicolon.strings": '"a" = { b = c };',
    "data.strings": '"a" = <0102 abCD\n ef>;\n"b" = <>;',
    "data-odd.strings": '"a" = <012>;',
    "data-invalid.strings": '"a" = <01zz>;',
    "top-dictionary.strings": "{ a = b; c = (d, e); }",
    "top-array.strings": '(a, "b", <01>)',
    "top-string.strings": '"just a string"',
    "top-dictionary-junk.strings": "{ a = b; } c",
    "top-array-junk.strings": "(a) b",
    "json.strings": '{"a": "b"}',
    "depth-strings-512.strings": strings_depth(512),
    "depth-strings-513.strings": strings_depth(513),
    "depth-arrays-513.strings": "(" * 513 + ")" * 513,
    "depth-arrays-514.strings": "(" * 514 + ")" * 514,
}

# Encodings, written as bytes.
OPENSTEP_BYTES = {
    "utf8-bom.strings": b'\xef\xbb\xbf"a" = "b";',
    "utf16le.strings": "\ufeff\"a\" = \"v\u00e4lue\";".encode("utf-16-le"),
    "utf16be.strings": "\ufeff\"a\" = \"v\u00e4lue\";".encode("utf-16-be"),
    "utf16-no-bom.strings": '"a" = "b";'.encode("utf-16-le"),
    "utf16-odd-length.strings": "\ufeff\"a\" = \"b\";".encode("utf-16-le") + b"\x00",
    "latin1.strings": b'"a" = "\xe9";',
}


def main():
    out = Path(sys.argv[1])
    (out / "binary").mkdir(parents=True, exist_ok=True)
    (out / "xml").mkdir(parents=True, exist_ok=True)
    for name, data in BINARY.items():
        (out / "binary" / name).write_bytes(data)
    for name, text in XML.items():
        if text is not None:
            (out / "xml" / name).write_bytes(text.encode("utf-8"))
    (out / "xml" / "invalid-utf8.xml").write_bytes(b"<plist><string>\xff\xfe</string></plist>")
    (out / "xml" / "latin1.xml").write_bytes(
        b'<?xml version="1.0" encoding="ISO-8859-1"?><plist><string>\xe9</string></plist>')
    (out / "xml" / "utf16.xml").write_bytes(
        '<?xml version="1.0" encoding="UTF-16"?><plist><string>x</string></plist>'.encode("utf-16"))
    (out / "xml" / "shift-jis.xml").write_bytes(
        b'<?xml version="1.0" encoding="Shift_JIS"?><plist><string>x</string></plist>')
    (out / "openstep").mkdir(parents=True, exist_ok=True)
    for name, text in OPENSTEP.items():
        (out / "openstep" / name).write_bytes(text.encode("utf-8"))
    for name, data in OPENSTEP_BYTES.items():
        (out / "openstep" / name).write_bytes(data)


if __name__ == "__main__":
    main()
