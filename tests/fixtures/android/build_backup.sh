#!/bin/sh
# Rebuilds msec's backup rules fixtures from backup/: backup.apk (aapt2 link) and backup.aab
# (aapt2 link --proto-format, laid out as an app bundle's base module, unsigned), and
# backup/xmltree.txt: aapt2's dump of the manifest and both rule files in the APK, which the
# tests compare msec's reading against.
# Needs ANDROID_HOME (or the default macOS SDK location), build-tools 37.0.0, platform
# android-37.0, and python3.
set -eu
cd "$(dirname "$0")"
sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
aapt2="$sdk/build-tools/37.0.0/aapt2"
platform="$sdk/platforms/android-37.0/android.jar"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$aapt2" compile --dir backup/res -o "$work/res.zip"
"$aapt2" link -I "$platform" --manifest backup/AndroidManifest.xml -o backup.apk "$work/res.zip"
"$aapt2" link --proto-format -I "$platform" --manifest backup/AndroidManifest.xml \
  -o "$work/proto.zip" "$work/res.zip"
python3 -I - "$work/proto.zip" backup.aab <<'PY'
import sys, zipfile
linked, target = sys.argv[1:]
# BundleConfig { bundletool { version: "0.0.0-fixture" } }, as bundle/make_bundle.py writes it.
version = b"0.0.0-fixture"
config = bytes([0x0A, len(version) + 2, 0x12, len(version)]) + version
with zipfile.ZipFile(linked) as module, zipfile.ZipFile(target, "w") as bundle:
    def put(name, data):
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        bundle.writestr(info, data)
    put("BundleConfig.pb", config)
    for info in sorted(module.infolist(), key=lambda entry: entry.filename):
        name = info.filename
        if name == "AndroidManifest.xml":
            put("base/manifest/AndroidManifest.xml", module.read(info))
        else:
            put(f"base/{name}", module.read(info))
PY
{
  for file in AndroidManifest.xml res/xml/backup_rules.xml res/xml/data_extraction_rules.xml; do
    echo "== $file"
    "$aapt2" dump xmltree --file "$file" backup.apk
  done
} > backup/xmltree.txt
