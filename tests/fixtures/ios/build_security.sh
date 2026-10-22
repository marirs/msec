#!/bin/sh
# Rebuilds msec's iOS crypto, storage, WebView and logging fixtures and Apple's tools' reading
# of them (security-verdicts.txt). Each app is built for iOS devices with Xcode's clang and
# swiftc and signed ad hoc: an Objective-C main executable and a Swift framework
# (Frameworks/Lib.framework).
# - ipa/security.ipa (security/main.m, security/Lib.swift): NSLog, NSLogv and printf; Swift's
#   print and debugPrint; NSFileProtectionNone and NSURLFileProtectionNone; keychain items
#   stored with kSecAttrAccessibleAlways and kSecAttrAccessibleAlwaysThisDeviceOnly; UIWebView;
#   CryptoKit's Insecure.MD5 and Insecure.SHA1; the WebKit preferences
#   allowFileAccessFromFileURLs and allowUniversalAccessFromFileURLs set by key-value coding
#   (from Objective-C and from Swift);
# - ipa/security-clean.ipa (security/clean/): the safe counterpart of each: os_log and Logger
#   with private values, NSFileProtectionComplete, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
#   WKWebView with its default configuration, CryptoKit's SHA256;
# - ipa/security-incomplete.ipa: security-clean.ipa after signing, with its main executable
#   encrypted as the App Store delivers it (cryptid 1 and its cryptoff..cryptoff+cryptsize range
#   replaced by a keystream XOR, as build_encrypted.sh does: C strings unreadable, imports
#   readable) and its framework cut short at its __LINKEDIT segment (no symbol table, so no
#   import can be read).
# security-verdicts.txt: per app and executable, the symbols `nm -u` lists that the checks look
# for, the WebKit preference keys `otool -v -s __TEXT __cstring` prints, and for the
# incomplete app otool's LC_ENCRYPTION_INFO_64 fields and what nm says of the cut framework.
# Needs macOS with Xcode (an iOS SDK, clang, swiftc, nm, otool) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
cc="xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot $sdk -Os -fobjc-arc \
  -fstack-protector-strong"
swiftc="xcrun --sdk iphoneos swiftc -target arm64-apple-ios17.0 -sdk $sdk -O"

# Writes the app's and the framework's Info.plist (binary) into a bundle.
info() { # bundle, bundle identifier
  python3 -I - "$1" "$2" <<'PY'
import plistlib
import sys
from pathlib import Path
app, identifier = Path(sys.argv[1]), sys.argv[2]
common = {"CFBundleInfoDictionaryVersion": "6.0", "CFBundleShortVersionString": "1.0",
          "CFBundleVersion": "1", "MinimumOSVersion": "17.0",
          "CFBundleSupportedPlatforms": ["iPhoneOS"], "DTPlatformName": "iphoneos",
          "DTSDKName": "iphoneos27.1", "DTXcode": "2710"}
def write(path, content):
    path.write_bytes(plistlib.dumps(content, fmt=plistlib.FMT_BINARY))
write(app / "Info.plist", {**common, "CFBundleIdentifier": identifier,
      "CFBundleExecutable": "Fixture", "CFBundleName": "Security",
      "CFBundlePackageType": "APPL", "UIDeviceFamily": [1], "LSRequiresIPhoneOS": True})
write(app / "Frameworks/Lib.framework/Info.plist", {**common,
      "CFBundleIdentifier": identifier + ".lib", "CFBundleExecutable": "Lib",
      "CFBundlePackageType": "FMWK"})
PY
}

# Builds and signs one app: sources from a directory holding main.m and Lib.swift.
build() { # sources, bundle, bundle identifier
  sources="$1" app="$2"
  mkdir -p "$app/Frameworks/Lib.framework"
  $swiftc -emit-library -module-name Lib \
    -Xlinker -install_name -Xlinker @rpath/Lib.framework/Lib \
    -o "$app/Frameworks/Lib.framework/Lib" "$sources/Lib.swift"
  # UIWebView is deprecated: the positive app uses it on purpose.
  $cc -Wno-deprecated-declarations -framework Foundation -framework CoreGraphics \
    -framework Security -framework UIKit -framework WebKit -F "$app/Frameworks" -framework Lib \
    -Wl,-rpath,@executable_path/Frameworks -o "$app/Fixture" "$sources/main.m"
  info "$app" "$3"
  codesign -s - -f --timestamp=none "$app/Frameworks/Lib.framework" > /dev/null 2>&1
  codesign -s - -f --timestamp=none "$app" > /dev/null 2>&1
}

build security "$work/positive/Fixture.app" dev.appchk.security
build security/clean "$work/clean/Fixture.app" dev.appchk.security.clean
mkdir -p "$work/incomplete"
cp -R "$work/clean/Fixture.app" "$work/incomplete/Fixture.app"
incomplete="$work/incomplete/Fixture.app"

# The App Store's encryption of the main executable (as build_encrypted.sh), and the
# framework cut at its __LINKEDIT segment's file offset.
python3 -I - "$incomplete/Fixture" "$incomplete/Frameworks/Lib.framework/Lib" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO_64 = 0x2C

def commands(data):
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<8I", data, 0)
    assert magic == 0xFEEDFACF, "a thin 64-bit Mach-O file"
    at = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<2I", data, at)
        yield cmd, at
        at += size

main = Path(sys.argv[1])
data = bytearray(main.read_bytes())
for cmd, at in commands(data):
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
else:
    raise SystemExit("no LC_ENCRYPTION_INFO_64")
main.write_bytes(bytes(data))

library = Path(sys.argv[2])
data = library.read_bytes()
for cmd, at in commands(data):
    if cmd == LC_SEGMENT_64 and data[at + 8:at + 24].rstrip(b"\0") == b"__LINKEDIT":
        fileoff = struct.unpack_from("<Q", data, at + 40)[0]
        library.write_bytes(data[:fileoff])
        break
else:
    raise SystemExit("no __LINKEDIT")
PY
mkdir -p "$incomplete/SC_Info"
printf 'msec placeholder sinf' > "$incomplete/SC_Info/Fixture.sinf"
printf 'msec placeholder supp' > "$incomplete/SC_Info/Fixture.supp"

python3 -I make_ipa.py ipa ipa/security.ipa payload "$work/positive/Fixture.app"
python3 -I make_ipa.py ipa ipa/security-clean.ipa payload "$work/clean/Fixture.app"
python3 -I make_ipa.py ipa ipa/security-incomplete.ipa payload "$incomplete"

# What the checks look for, as Apple's tools list it.
symbols='NSLog|NSLogv|printf|\$ss5print_9separator10terminatoryypd_S2StF|\$ss10debugPrint_9separator10terminatoryypd_S2StF|NSFileProtectionNone|NSURLFileProtectionNone|kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly|OBJC_CLASS_\$_UIWebView|OBJC_METACLASS_\$_UIWebView|\$s9CryptoKit8InsecureO.*'
keys='allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs'
{
  for variant in positive clean incomplete; do
    for binary in Fixture Frameworks/Lib.framework/Lib; do
      path="$work/$variant/Fixture.app/$binary"
      echo "$variant $binary:"
      if ! xcrun nm -u "$path" > "$work/imports" 2> "$work/nm-error"; then
        sed -E 's/^.*: //; s/^/  nm error: /' "$work/nm-error" | head -1
      fi
      sed -E 's/^_//' "$work/imports" | grep -E "^($symbols)$" | sed 's/^/  import /' || true
      xcrun otool -v -s __TEXT __cstring "$path" 2> /dev/null | sed -E 's/^[0-9a-f]+[[:space:]]+//' \
        | grep -E "^($keys)$" | sort -u | sed 's/^/  string /' || true
      if [ "$variant" = incomplete ] && [ "$binary" = Fixture ]; then
        xcrun otool -l "$path" | grep -A4 LC_ENCRYPTION_INFO_64 \
          | grep -E '^ +(cryptoff|cryptsize|cryptid) ' | sed -E 's/^ +/  /'
      fi
    done
  done
} > security-verdicts.txt
