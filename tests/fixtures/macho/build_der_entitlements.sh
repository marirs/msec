#!/bin/sh
# Rebuilds msec's DER entitlements fixtures and codesign's reading of them:
# - der/der-entitlements: a C executable for iOS, ad-hoc signed by codesign with entitlements
#   of every value type (true and false, strings including non-ASCII, positive and negative
#   integers, arrays, a nested dictionary), which codesign embeds both as XML and as DER;
# - der/der-entitlements-mismatch: the same, with get-task-allow changed from true to false in
#   the DER entitlements only and their special-slot hash updated, so the signature still
#   verifies while the two encodings disagree (iOS 15 and later read the DER ones);
# - der/der-entitlements.xml: the XML entitlements codesign embedded (codesign -d
#   --entitlements - --xml), which the DER ones must equal;
# - der/der-entitlements.verify.txt: codesign --verify's verdict on both binaries.
# Needs macOS with Xcode (an iOS SDK) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
printf 'int main(void) { return 0; }\n' > "$work/main.c"
xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot "$sdk" -Os \
  -o "$work/der-entitlements" "$work/main.c"
cat > "$work/entitlements.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>A1B2C3D4E5.dev.appchk.fixture</string>
	<key>get-task-allow</key>
	<true/>
	<key>com.apple.developer.fixture.disabled</key>
	<false/>
	<key>com.apple.developer.fixture.name</key>
	<string>Fixture ünïcode ✓</string>
	<key>com.apple.developer.fixture.count</key>
	<integer>300</integer>
	<key>com.apple.developer.fixture.offset</key>
	<integer>-2</integer>
	<key>keychain-access-groups</key>
	<array>
		<string>A1B2C3D4E5.dev.appchk.fixture</string>
		<string>A1B2C3D4E5.shared</string>
	</array>
	<key>com.apple.developer.fixture.nested</key>
	<dict>
		<key>enabled</key>
		<true/>
		<key>levels</key>
		<array>
			<integer>1</integer>
			<string>two</string>
		</array>
	</dict>
</dict>
</plist>
PLIST
codesign -s - -f --timestamp=none --generate-entitlement-der \
  --entitlements "$work/entitlements.plist" "$work/der-entitlements" > /dev/null 2>&1
mkdir -p der
cp "$work/der-entitlements" der/der-entitlements
codesign -d --entitlements - --xml der/der-entitlements 2> /dev/null > der/der-entitlements.xml
python3 -I - der/der-entitlements der/der-entitlements-mismatch <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

data = bytearray(Path(sys.argv[1]).read_bytes())
ncmds = struct.unpack_from("<I", data, 16)[0]
offset = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from("<II", data, offset)
    if cmd == 0x1D:
        data_offset = struct.unpack_from("<I", data, offset + 8)[0]
    offset += size
_, _, count = struct.unpack_from(">III", data, data_offset)
blobs = {}
for index in range(count):
    slot, at = struct.unpack_from(">II", data, data_offset + 12 + 8 * index)
    length = struct.unpack_from(">I", data, data_offset + at + 4)[0]
    blobs[slot] = (data_offset + at, length)
der_at, der_length = blobs[7]
key = b"\x0c\x0eget-task-allow\x01\x01\xff"
where = data.index(key, der_at, der_at + der_length)
data[where + len(key) - 1] = 0x00
cd_at, _ = blobs[0]
hash_offset, _, special = struct.unpack_from(">III", data, cd_at + 16)
hash_size = data[cd_at + 36]
slot_at = cd_at + hash_offset - 7 * hash_size
data[slot_at : slot_at + hash_size] = hashlib.sha256(data[der_at : der_at + der_length]).digest()[:hash_size]
Path(sys.argv[2]).write_bytes(bytes(data))
PY
for binary in der-entitlements der-entitlements-mismatch; do
  if codesign --verify "der/$binary" > /dev/null 2> "$work/log"; then
    echo "$binary: valid"
  else
    echo "$binary: $(sed "s|der/||" "$work/log" | head -n 1)"
  fi
done > der/der-entitlements.verify.txt
