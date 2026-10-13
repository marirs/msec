#!/bin/sh
# Rebuilds the Android fixtures with aapt2 from the Android SDK. Needs ANDROID_HOME (or the
# default macOS SDK location), build-tools 37.0.0 and platform android-37.0.
set -eu
cd "$(dirname "$0")"
sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
aapt2="$sdk/build-tools/37.0.0/aapt2"
platform="$sdk/platforms/android-37.0/android.jar"
for fixture in basic; do
  work="$(mktemp -d)"
  "$aapt2" compile --dir "$fixture/res" -o "$work/res.zip"
  "$aapt2" link -I "$platform" --manifest "$fixture/AndroidManifest.xml" -o "$fixture.apk" "$work/res.zip"
  "$aapt2" dump xmltree --file AndroidManifest.xml "$fixture.apk" > "$fixture.xmltree.txt"
  rm -rf "$work"
done
