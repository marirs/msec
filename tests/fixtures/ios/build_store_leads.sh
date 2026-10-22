#!/bin/sh
# Rebuilds msec's iOS store-lead fixtures (ipa/leads*.ipa) and Apple's tools' reading of them
# (leads-verdicts.txt). Each app is built for iOS devices with Xcode's clang and signed ad hoc,
# with two stand-in frameworks: Frameworks/Stripe.framework (leads/stripe.c) and
# Frameworks/GoogleSignIn.framework (leads/googlesignin.m, defining GIDSignIn).
# - ipa/leads.ipa (leads/main.m): Stripe without StoreKit; GIDSignIn without Sign in with
#   Apple; createUserWithEmail:password:completion: without a deletion selector; linked against
#   a library installed at /System/Library/PrivateFrameworks/AppchkFixture.framework (built
#   from leads/private.c for linking only, not shipped), and a C string naming
#   FrontBoardServices.framework for dlopen;
# - ipa/leads-clean.ipa (leads/clean/main.m): StoreKit and ASAuthorizationAppleIDProvider
#   beside them, deleteWithCompletion: beside account creation, no private framework, and
#   universal links (leads/clean/entitlements.plist: applinks:leads.example.com);
# Both apps register the custom URL scheme "leads".
# - ipa/leads-incomplete.ipa: leads-clean.ipa after signing, with its main executable
#   encrypted as the App Store delivers it (as build_encrypted.sh does): method names and C
#   strings unreadable, imports and load commands readable.
# leads-verdicts.txt: per app and executable, otool -L's libraries, the classes nm -u lists
# among those the checks read, the selectors otool prints in __objc_methname, and the private
# framework paths in __cstring.
# Needs macOS with Xcode (an iOS SDK, clang, otool, nm) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
cc="xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot $sdk -Os -fobjc-arc \
  -fstack-protector-strong"

# The library the positive app links from the private frameworks directory.
mkdir -p "$work/private"
$cc -dynamiclib \
  -install_name /System/Library/PrivateFrameworks/AppchkFixture.framework/AppchkFixture \
  -o "$work/private/libAppchkFixture.dylib" leads/private.c

info() { # bundle
  python3 -I - "$1" <<'PY'
import plistlib
import sys
from pathlib import Path
app = Path(sys.argv[1])
# Both apps register the custom URL scheme "leads".
common = {"CFBundleInfoDictionaryVersion": "6.0", "CFBundleShortVersionString": "1.0",
          "CFBundleVersion": "1", "MinimumOSVersion": "17.0",
          "CFBundleSupportedPlatforms": ["iPhoneOS"], "DTPlatformName": "iphoneos",
          "DTSDKName": "iphoneos27.1", "DTXcode": "2710"}
def write(path, content):
    path.write_bytes(plistlib.dumps(content, fmt=plistlib.FMT_BINARY))
write(app / "Info.plist", {**common, "CFBundleIdentifier": "dev.appchk.leads",
      "CFBundleExecutable": "Fixture", "CFBundleName": "Leads",
      "CFBundlePackageType": "APPL", "UIDeviceFamily": [1], "LSRequiresIPhoneOS": True,
      "CFBundleURLTypes": [{"CFBundleURLName": "dev.appchk.leads",
                            "CFBundleURLSchemes": ["leads"]}]})
for name in ("Stripe", "GoogleSignIn"):
    write(app / f"Frameworks/{name}.framework/Info.plist", {**common,
          "CFBundleIdentifier": f"dev.appchk.leads.{name.lower()}", "CFBundleExecutable": name,
          "CFBundlePackageType": "FMWK"})
PY
}

build() { # main source, bundle, entitlements ("" for none), extra linker arguments...
  source="$1" app="$2" entitlements="$3"
  shift 3
  mkdir -p "$app/Frameworks/Stripe.framework" "$app/Frameworks/GoogleSignIn.framework"
  $cc -dynamiclib -install_name @rpath/Stripe.framework/Stripe \
    -o "$app/Frameworks/Stripe.framework/Stripe" leads/stripe.c
  $cc -dynamiclib -framework Foundation -install_name @rpath/GoogleSignIn.framework/GoogleSignIn \
    -o "$app/Frameworks/GoogleSignIn.framework/GoogleSignIn" leads/googlesignin.m
  $cc -framework Foundation -F "$app/Frameworks" -framework Stripe -framework GoogleSignIn \
    -Wl,-rpath,@executable_path/Frameworks "$@" -o "$app/Fixture" "$source"
  info "$app"
  codesign -s - -f --timestamp=none "$app/Frameworks/Stripe.framework" > /dev/null 2>&1
  codesign -s - -f --timestamp=none "$app/Frameworks/GoogleSignIn.framework" > /dev/null 2>&1
  if [ -n "$entitlements" ]; then
    codesign -s - -f --timestamp=none --entitlements "$entitlements" "$app" > /dev/null 2>&1
  else
    codesign -s - -f --timestamp=none "$app" > /dev/null 2>&1
  fi
}

build leads/main.m "$work/positive/Fixture.app" "" "$work/private/libAppchkFixture.dylib"
build leads/clean/main.m "$work/clean/Fixture.app" leads/clean/entitlements.plist \
  -framework StoreKit -framework AuthenticationServices
mkdir -p "$work/incomplete"
cp -R "$work/clean/Fixture.app" "$work/incomplete/Fixture.app"
incomplete="$work/incomplete/Fixture.app"
python3 -I - "$incomplete/Fixture" <<'PY'
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
mkdir -p "$incomplete/SC_Info"
printf 'msec placeholder sinf' > "$incomplete/SC_Info/Fixture.sinf"
printf 'msec placeholder supp' > "$incomplete/SC_Info/Fixture.supp"

python3 -I make_ipa.py ipa ipa/leads.ipa payload "$work/positive/Fixture.app"
python3 -I make_ipa.py ipa ipa/leads-clean.ipa payload "$work/clean/Fixture.app"
python3 -I make_ipa.py ipa ipa/leads-incomplete.ipa payload "$incomplete"

classes='GIDSignIn|ASAuthorizationAppleIDProvider|ASAuthorizationAppleIDButton|SKPaymentQueue'
selectors='createUserWithEmail:password:completion:|deleteWithCompletion:'
{
  for variant in positive clean incomplete; do
    path="$work/$variant/Fixture.app/Fixture"
    echo "$variant Fixture:"
    xcrun otool -L "$path" | tail -n +2 | sed -E 's/^[[:space:]]+//; s/ \(compatibility.*$//; s/^/  library /'
    xcrun nm -u "$path" | sed -E 's/^_OBJC_CLASS_\$_//' | grep -E "^($classes)$" \
      | sed 's/^/  class /' || true
    xcrun otool -v -s __TEXT __objc_methname "$path" 2> /dev/null | tr ' \t' '\n\n' \
      | grep -E "^($selectors)$" | sort -u | sed 's/^/  selector /' || true
    xcrun otool -v -s __TEXT __cstring "$path" 2> /dev/null \
      | grep -o '/System/Library/PrivateFrameworks/[^[:space:]]*' | sort -u \
      | sed 's/^/  string /' || true
    # The key has dots, which plutil's key paths split on: read it with plistlib.
    codesign -d --entitlements - --xml "$path" 2> /dev/null | python3 -I -c '
import plistlib, sys
data = sys.stdin.buffer.read()
domains = plistlib.loads(data).get("com.apple.developer.associated-domains", []) if data else []
for domain in domains:
    print("  associated-domain " + domain)'
    python3 -I -c '
import plistlib, sys
info = plistlib.load(open(sys.argv[1], "rb"))
for kind in info.get("CFBundleURLTypes", []):
    for scheme in kind.get("CFBundleURLSchemes", []):
        print("  url-scheme " + scheme)' "$work/$variant/Fixture.app/Info.plist"
  done
} > leads-verdicts.txt
