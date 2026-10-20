#!/bin/sh
# Rebuilds msec's IPA fixtures and iOS's verdicts on them:
# - ipa/<variant>.ipa: the fixture app (app/: an Objective-C executable under ARC, an embedded
#   framework with its own privacy manifest, a loose library, a share extension, a privacy
#   manifest, a localization) built for iOS devices with Xcode's clang, ad-hoc signed with
#   entitlements, and packaged by make_ipa.py; one IPA per Info.plist variant
#   (make_ipa.py VARIANTS), each changed in one way and signed again, and two changed after
#   signing (make_ipa.py TAMPER: Info.plist, one byte of the executable);
# - ipa/layout-*.ipa: the fixture in other archive layouts (two apps, no Payload directory, no
#   .app directory, no entries);
# - install-verdicts.txt: the same variants built for the iOS simulator and installed into a
#   temporary simulator device: whether iOS's installer accepts each, and for those it
#   accepts, the bundle identifier it registered (which shows which duplicate key it used);
# - codesign-verdicts.txt: codesign --verify --deep --strict on each device bundle (the
#   simulator's installer does not check signatures);
# - bundle.txt: the device bundle's file list, and plutil's reading of its Info.plist;
#   fixture-Info.plist.xml: plutil's XML conversion of that Info.plist.
# Needs macOS with Xcode (an iOS SDK and an iOS simulator runtime) and python3. Creates and
# deletes its own simulator device; nothing else is touched.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
device_id=""
cleanup() {
  if [ -n "$device_id" ]; then
    xcrun simctl shutdown "$device_id" > /dev/null 2>&1 || true
    xcrun simctl delete "$device_id" > /dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# Builds the unsigned bundle for a platform into $work/<platform>/Fixture.app.
build() { # platform: iphoneos or iphonesimulator
  platform="$1"
  case "$platform" in
    iphoneos) target=arm64-apple-ios17.0 ;;
    *) target=arm64-apple-ios17.0-simulator ;;
  esac
  sdk="$(xcrun --sdk "$platform" --show-sdk-path)"
  cc="xcrun --sdk $platform clang -target $target -isysroot $sdk -Os -fstack-protector-strong"
  app="$work/$platform/Fixture.app"
  mkdir -p "$app/Frameworks/Lib.framework" "$app/PlugIns/Share.appex" "$app/en.lproj"
  python3 -I make_ipa.py info "$platform" "$work/$platform/info"
  $cc -dynamiclib -install_name @rpath/Lib.framework/Lib -o "$app/Frameworks/Lib.framework/Lib" \
    app/Lib/lib.c
  plutil -convert binary1 -o "$app/Frameworks/Lib.framework/Info.plist" "$work/$platform/info/Lib.plist"
  cp app/PrivacyInfo.xcprivacy "$app/Frameworks/Lib.framework/PrivacyInfo.xcprivacy"
  $cc -dynamiclib -install_name @rpath/libextra.dylib -o "$app/Frameworks/libextra.dylib" app/extra.c
  $cc -fobjc-arc -framework Foundation -F "$app/Frameworks" -framework Lib \
    -Wl,-rpath,@executable_path/Frameworks -o "$app/Fixture" app/main.m
  $cc -Wl,-rpath,@executable_path/../../Frameworks -o "$app/PlugIns/Share.appex/Share" app/Share/main.c
  plutil -convert binary1 -o "$app/PlugIns/Share.appex/Info.plist" "$work/$platform/info/Share.plist"
  plutil -convert binary1 -o "$app/Info.plist" "$work/$platform/info/app.plist"
  cp app/PrivacyInfo.xcprivacy "$app/PrivacyInfo.xcprivacy"
  plutil -convert binary1 -o "$app/en.lproj/InfoPlist.strings" app/InfoPlist.strings
}

# Ad-hoc signs a bundle inside out, as Xcode does; a variant codesign refuses stays unsigned.
sign() { # bundle
  codesign -s - -f --timestamp=none "$1/Frameworks/Lib.framework" > /dev/null 2>&1 || true
  codesign -s - -f --timestamp=none "$1/Frameworks/libextra.dylib" > /dev/null 2>&1 || true
  codesign -s - -f --timestamp=none "$1/PlugIns/Share.appex" > /dev/null 2>&1 || true
  codesign -s - -f --timestamp=none --entitlements app/entitlements.plist "$1" > /dev/null 2>&1 || true
}

variants() { # platform
  python3 -I make_ipa.py variants "$work/$1/Fixture.app" "$work/$1/variants"
  for bundle in "$work/$1"/variants/*/Fixture.app; do
    sign "$bundle"
  done
  python3 -I make_ipa.py tamper "$work/$1/variants"
}

build iphoneos
variants iphoneos
rm -rf ipa
mkdir ipa
for bundle in "$work"/iphoneos/variants/*/Fixture.app; do
  variant="$(basename "$(dirname "$bundle")")"
  python3 -I make_ipa.py ipa "ipa/$variant.ipa" payload "$bundle"
done
fixture="$work/iphoneos/variants/fixture/Fixture.app"
for layout in two-apps not-in-payload no-app empty; do
  python3 -I make_ipa.py ipa "ipa/layout-$layout.ipa" "$layout" "$fixture"
done
# codesign's verdict on each device bundle (the simulator's installer does not check
# signatures, so this is the oracle for them).
for bundle in "$work"/iphoneos/variants/*/Fixture.app; do
  variant="$(basename "$(dirname "$bundle")")"
  if codesign --verify --deep --strict "$bundle" > /dev/null 2> "$work/log"; then
    echo "$variant: valid"
  else
    echo "$variant: $(sed -e "s|$bundle|Fixture.app|g" -e "s|$work/iphoneos/variants/[^/]*/||g" "$work/log" | head -n 1 | cut -c 1-160)"
  fi
done > codesign-verdicts.txt
{
  echo "# Files of ipa/fixture.ipa's bundle"
  (cd "$fixture/.." && find Fixture.app -type f | LC_ALL=C sort)
  echo "# plutil -p Fixture.app/Info.plist"
  plutil -p "$fixture/Info.plist"
} > bundle.txt
# Apple's XML for the fixture's Info.plist, which the tests compare msec's reading with.
plutil -convert xml1 -o fixture-Info.plist.xml "$fixture/Info.plist"

build iphonesimulator
variants iphonesimulator
# An iPhone type and iOS runtime known to work together: those of an existing iPhone device on
# the newest iOS runtime that has one.
pair="$(xcrun simctl list devices available -j | python3 -I -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
for runtime in sorted((r for r in devices if ".iOS-" in r), reverse=True):
    for device in devices[runtime]:
        if device["name"].startswith("iPhone"):
            print(device["deviceTypeIdentifier"], runtime)
            raise SystemExit
')"
device_id="$(xcrun simctl create msec-ipa-fixtures $pair)"
xcrun simctl boot "$device_id"
xcrun simctl bootstatus "$device_id" -b > /dev/null
for bundle in "$work"/iphonesimulator/variants/*/Fixture.app; do
  variant="$(basename "$(dirname "$bundle")")"
  if xcrun simctl install "$device_id" "$bundle" > /dev/null 2> "$work/log"; then
    installed=""
    for identifier in dev.appchk.fixture dev.appchk.first; do
      if xcrun simctl get_app_container "$device_id" "$identifier" > /dev/null 2>&1; then
        installed="$identifier"
        xcrun simctl uninstall "$device_id" "$identifier"
      fi
    done
    echo "$variant: installed as ${installed:-unknown}"
  else
    # The installer's specific reason: the outer error's lines, without its generic ones.
    reason="$(sed -n '2,/^Underlying error/p' "$work/log" | grep -v -e '^Underlying error' \
      -e '^App installation failed' -e '^Please try again later' -e '^Simulator device failed' |
      tr '\n' ' ' | sed -e 's/ *$//' -e 's|/[^ ]*/\(Fixture\.app\)|\1|g' | cut -c 1-200)"
    echo "$variant: refused: ${reason:-$(head -n 1 "$work/log" | cut -c 1-160)}"
  fi
done > install-verdicts.txt
