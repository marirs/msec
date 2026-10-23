#!/bin/sh
# Rebuilds ipa/loose-libraries.ipa: ipa/fixture.ipa with two more loose libraries, laid out as
# Xcode leaves them in apps with Swift code:
# - Frameworks/libplist.dylib carries its own Info.plist in a __TEXT,__info_plist section, which
#   its signature binds (Apple's Swift runtime libraries do this);
# - libroot.dylib sits at the bundle root (Xcode copies libswiftRemoteMirror.dylib there).
# Both are signed ad hoc, then the app is signed again over them.
# loose-libraries-verdicts.txt: per library, codesign --verify's verdict and codesign -dv's
# Info.plist line (which says what the signature binds).
# Needs macOS with Xcode (an iOS SDK, codesign) and python3. Run after build_ipa.sh.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
cc="xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot $sdk -Os -fstack-protector-strong"

mkdir -p "$work/unpacked"
(cd "$work/unpacked" && unzip -q "$OLDPWD/ipa/fixture.ipa")
bundle="$work/unpacked/Payload/Fixture.app"
plutil -create xml1 "$work/Info.plist"
plutil -insert CFBundleIdentifier -string dev.appchk.fixture.plist "$work/Info.plist"
plutil -insert CFBundleName -string libplist "$work/Info.plist"
plutil -insert CFBundleShortVersionString -string 1.0 "$work/Info.plist"
$cc -dynamiclib -install_name @rpath/libplist.dylib \
  -Wl,-sectcreate,__TEXT,__info_plist,"$work/Info.plist" \
  -o "$bundle/Frameworks/libplist.dylib" app/extra.c
$cc -dynamiclib -install_name @rpath/libroot.dylib -o "$bundle/libroot.dylib" app/extra.c
codesign -s - -f --timestamp=none "$bundle/Frameworks/libplist.dylib" > /dev/null 2>&1
codesign -s - -f --timestamp=none "$bundle/libroot.dylib" > /dev/null 2>&1
codesign -s - -f --timestamp=none --entitlements app/entitlements.plist "$bundle" > /dev/null 2>&1
python3 -I make_ipa.py ipa ipa/loose-libraries.ipa payload "$bundle"

{
  for library in Frameworks/libplist.dylib libroot.dylib; do
    echo "$library:"
    # codesign names the file by its temporary path: keep only what follows it.
    codesign --verify --verbose=1 "$bundle/$library" 2>&1 | sed 's#^.*/Fixture.app/##; s/^/  verify: /'
    codesign -dv "$bundle/$library" 2>&1 | grep '^Info.plist' | sed 's/^/  /'
  done
} > loose-libraries-verdicts.txt
