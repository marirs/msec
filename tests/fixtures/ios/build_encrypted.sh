#!/bin/sh
# Rebuilds msec's App Store-encrypted fixture (ipa/encrypted.ipa) and otool's reading of it
# (encrypted-verdicts.txt). Run after build_privacy.sh: the IPA is ipa/privacy.ipa as the App
# Store would deliver it, with its main executable encrypted:
# - Payload/Fixture.app/Fixture has LC_ENCRYPTION_INFO_64's cryptid set to 1 and every byte of
#   its cryptoff..cryptoff+cryptsize range replaced by a keystream XOR (FairPlay's ciphertext
#   is not reproducible; any bytes that are not the plaintext stand in for it). The range
#   covers __text, __cstring and __objc_methname; the load commands, the symbol table and the
#   code signature stay readable, as in an App Store download;
# - SC_Info/Fixture.sinf and Fixture.supp, FairPlay's metadata files, hold placeholder bytes.
# The frameworks are left as they are, so one executable is encrypted and two are not.
# encrypted-verdicts.txt: per executable, otool -l's LC_ENCRYPTION_INFO_64 fields and the
# file offset (decimal) and size (hex) of its __TEXT,__cstring and __TEXT,__objc_methname
# sections.
# Needs macOS with Xcode (otool) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(cd "$work" && unzip -q "$OLDPWD/ipa/privacy.ipa")
app="$work/Payload/Fixture.app"
python3 -I - "$app/Fixture" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

LC_ENCRYPTION_INFO_64 = 0x2C
path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<8I", data, 0)
assert magic == 0xFEEDFACF, "a thin 64-bit Mach-O file"
at = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<2I", data, at)
    if cmd == LC_ENCRYPTION_INFO_64:
        offset, length, _ = struct.unpack_from("<3I", data, at + 8)
        struct.pack_into("<I", data, at + 16, 1)
        stream = b""
        counter = 0
        while len(stream) < length:
            stream += hashlib.sha256(b"msec fixture" + counter.to_bytes(4, "little")).digest()
            counter += 1
        for index in range(length):
            data[offset + index] ^= stream[index]
        break
    at += size
else:
    raise SystemExit("no LC_ENCRYPTION_INFO_64")
path.write_bytes(bytes(data))
PY
mkdir -p "$app/SC_Info"
printf 'msec placeholder sinf' > "$app/SC_Info/Fixture.sinf"
printf 'msec placeholder supp' > "$app/SC_Info/Fixture.supp"
python3 -I make_ipa.py ipa ipa/encrypted.ipa payload "$app"
{
  for binary in Fixture Frameworks/Lib.framework/Lib Frameworks/Alamofire.framework/Alamofire; do
    echo "$binary:"
    xcrun otool -l "$app/$binary" | grep -A4 LC_ENCRYPTION_INFO_64 \
      | grep -E '^ +(cryptoff|cryptsize|cryptid) ' | sed -E 's/^ +/  /'
    for section in __cstring __objc_methname; do
      xcrun otool -l "$app/$binary" | grep -A5 "sectname $section\$" \
        | awk -v name="$section" '$1 == "size" { size = $2 } $1 == "offset" { offset = $2 }
            END { if (offset != "") printf "  %s %d %s\n", name, offset, size }'
    done
  done
} > encrypted-verdicts.txt
