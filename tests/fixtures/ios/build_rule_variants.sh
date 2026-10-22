#!/bin/sh
# Rebuilds msec's rule-variant fixtures (ipa/variant-*.ipa): ipa/fixture.ipa changed in one way
# each, for checks no other IPA fixture triggers, and Apple's tools' reading of each
# (variant-verdicts.txt). Run after build_ipa.sh and macho/build_macho.sh.
# - variant-no-pie, -stack-exec, -manual, -debug, -unfortified: the main executable replaced by
#   macho/bin's no-pie (MH_PIE cleared), stack-exec (MH_ALLOW_STACK_EXECUTION set), manual
#   (Objective-C without ARC), debug (not stripped) and unfortified (strcpy without
#   _FORTIFY_SOURCE), then the bundle signed ad hoc with app/entitlements.plist;
# - variant-random-rpath: an executable from variants/random.c (rand and srand) linked with
#   LC_RPATH /usr/local/lib, signed the same way;
# - variant-unsigned: the main executable replaced by macho/bin/unsigned (no signature), the
#   bundle not signed again;
# - variant-der-mismatch: the main executable replaced by macho/der/der-entitlements-mismatch
#   (DER entitlements that differ from its XML ones), not signed again, which would rewrite
#   them;
# - variant-ats-exceptions: Info.plist's NSAppTransportSecurity replaced by arbitrary loads in
#   web content and for media, local networking, and example.com allowing insecure HTTP without
#   forward secrecy (NSAllowsArbitraryLoads unset), then the bundle signed again.
# variant-verdicts.txt, per variant: otool -hv's flags (PIE, ALLOW_STACK_EXECUTION), otool -l's
# LC_RPATH paths, the symbols nm -u lists among those the checks read, the debug entries nm -ap
# counts, codesign -dv's signature line, and plutil's NSAppTransportSecurity.
# Needs macOS with Xcode (an iOS SDK, otool, nm, codesign, plutil) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
macho=../macho

unpack() { # name: fixture.ipa unpacked into $work/<name>; prints the bundle path
  mkdir -p "$work/$1"
  (cd "$work/$1" && unzip -q "$OLDPWD/ipa/fixture.ipa")
  echo "$work/$1/Payload/Fixture.app"
}

sign() { # bundle
  codesign -s - -f --timestamp=none --entitlements app/entitlements.plist "$1" > /dev/null 2>&1
}

package() { # name, bundle
  python3 -I make_ipa.py ipa "ipa/variant-$1.ipa" payload "$2"
}

rm -f ipa/variant-*.ipa
for name in no-pie stack-exec manual debug unfortified; do
  bundle="$(unpack "$name")"
  cp "$macho/bin/$name" "$bundle/Fixture"
  sign "$bundle"
  package "$name" "$bundle"
done

bundle="$(unpack random-rpath)"
xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot "$sdk" -Os \
  -fstack-protector-strong -Wl,-rpath,/usr/local/lib -o "$bundle/Fixture" variants/random.c
sign "$bundle"
package random-rpath "$bundle"

bundle="$(unpack unsigned)"
cp "$macho/bin/unsigned" "$bundle/Fixture"
package unsigned "$bundle"

bundle="$(unpack der-mismatch)"
cp "$macho/der/der-entitlements-mismatch" "$bundle/Fixture"
package der-mismatch "$bundle"

bundle="$(unpack ats-exceptions)"
plutil -replace NSAppTransportSecurity -json '{"NSAllowsArbitraryLoadsInWebContent": true,
  "NSAllowsArbitraryLoadsForMedia": true, "NSAllowsLocalNetworking": true,
  "NSExceptionDomains": {"example.com": {"NSExceptionAllowsInsecureHTTPLoads": true,
  "NSExceptionRequiresForwardSecrecy": false}}}' "$bundle/Info.plist"
sign "$bundle"
package ats-exceptions "$bundle"

symbols='___stack_chk_fail|___stack_chk_guard|_objc_release|_objc_retain|_objc_autoreleasePoolPush|_strcpy|___strcpy_chk|_rand|_srand'
{
  for variant in no-pie stack-exec manual debug unfortified random-rpath unsigned der-mismatch \
    ats-exceptions; do
    bundle="$work/$variant/Payload/Fixture.app"
    echo "variant-$variant:"
    flags=$(xcrun otool -hv "$bundle/Fixture" | tail -1 | tr -s ' ' '\n' |
      grep -E '^(PIE|ALLOW_STACK_EXECUTION)$' | tr '\n' ' ')
    echo "  flags: ${flags:-none}"
    xcrun otool -l "$bundle/Fixture" | awk '$1 == "cmd" { cmd = $2 } cmd == "LC_RPATH" && $1 == "path" { print "  rpath: " $2 }'
    xcrun nm -u "$bundle/Fixture" | grep -E "^($symbols)\$" | sed 's/^/  import /' || true
    echo "  debug entries: $(xcrun nm -ap "$bundle/Fixture" | grep -c ' - ' || true)"
    # codesign names the file by its temporary path: keep only the verdict.
    signature=$(codesign -dv "$bundle/Fixture" 2>&1 | grep -E '^(Signature=|.*not signed)' |
      sed 's#^.*/Fixture: ##' || true)
    echo "  codesign: ${signature:-none}"
    echo "  ats: $(plutil -extract NSAppTransportSecurity json -o - "$bundle/Info.plist")"
  done
} > variant-verdicts.txt
