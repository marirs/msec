#!/bin/sh
# Rebuilds bundle-debuggable.aab: bundle-base.aab with its base module's manifest linked again
# by `aapt2 link --proto-format` from bundle/base/AndroidManifest.xml with
# android:debuggable="true" added to <application>, and its upload signature (META-INF)
# dropped, since it no longer covers the manifest. bundle-debuggable.xmltree.txt is aapt2's
# dump of that protobuf manifest. Run after build_bundle.sh.
# Needs ANDROID_HOME (or the default macOS SDK location), build-tools 37.0.0, platform
# android-37.0, and python3.
set -eu
cd "$(dirname "$0")"
sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
aapt2="$sdk/build-tools/37.0.0/aapt2"
platform="$sdk/platforms/android-37.0/android.jar"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sed 's/<application /<application android:debuggable="true" /' bundle/base/AndroidManifest.xml \
  > "$work/AndroidManifest.xml"
grep -q 'android:debuggable="true"' "$work/AndroidManifest.xml"
"$aapt2" compile --dir bundle/base/res -o "$work/res.zip"
"$aapt2" link --proto-format -I "$platform" --manifest "$work/AndroidManifest.xml" \
  -o "$work/base.zip" "$work/res.zip"
"$aapt2" dump xmltree --file AndroidManifest.xml "$work/base.zip" > bundle-debuggable.xmltree.txt
python3 -I - bundle-base.aab "$work/base.zip" bundle-debuggable.aab <<'PY'
import sys, zipfile
source, linked, target = sys.argv[1:]
manifest = zipfile.ZipFile(linked).read("AndroidManifest.xml")
with zipfile.ZipFile(source) as original, zipfile.ZipFile(target, "w") as debuggable:
    for info in original.infolist():
        if info.filename.startswith("META-INF/"):
            continue
        data = original.read(info)
        if info.filename == "base/manifest/AndroidManifest.xml":
            data = manifest
        debuggable.writestr(info, data)
PY
