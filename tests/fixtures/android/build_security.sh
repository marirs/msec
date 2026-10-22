#!/bin/sh
# Rebuilds msec's security code fixtures from security/:
# - security.apk: security/java/positive with security/AndroidManifest.xml (minSdk 16,
#   targetSdk 23): code a scanner should report for cryptography, storage, WebViews and
#   logging, and calls whose arguments are not constants at the call site (CallShapes);
# - security-clean.apk: security/java/clean with security/AndroidManifest-clean.xml: the same
#   features done safely, and no logging;
# - security-incomplete.apk: the clean app's classes.dex, and the positive code as a truncated
#   classes2.dex, so code checks cannot read all the code;
# - security/positive.disassembly.txt and security/clean.disassembly.txt: AOSP dexdump's
#   disassembly (-d) of each app's code, which the tests compare msec's call sites against.
# Needs ANDROID_HOME (or the default macOS SDK location), build-tools 37.0.0, platform
# android-37.0, and a JDK 17 or later (javac and java on PATH, or JAVA_HOME).
set -eu
cd "$(dirname "$0")"
sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
tools="$sdk/build-tools/37.0.0"
platform="$sdk/platforms/android-37.0/android.jar"
if [ -n "${JAVA_HOME:-}" ]; then PATH="$JAVA_HOME/bin:$PATH"; fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

build() { # variant, manifest, min API
  variant="$1" manifest="$2" api="$3"
  mkdir -p "$work/$variant/classes" "$work/$variant/dex"
  find "security/java/$variant" -name '*.java' | sort > "$work/$variant/sources"
  javac --release 8 -nowarn -Xlint:-options -encoding UTF-8 -cp "$platform" \
    -d "$work/$variant/classes" @"$work/$variant/sources"
  java -cp "$tools/lib/d8.jar" com.android.tools.r8.D8 --release --lib "$platform" \
    --min-api "$api" --output "$work/$variant/dex" \
    $(find "$work/$variant/classes" -name '*.class' | sort)
  "$tools/aapt2" compile --dir security/res -o "$work/$variant/res.zip"
  "$tools/aapt2" link -I "$platform" --manifest "$manifest" -o "$work/$variant/app.apk" \
    "$work/$variant/res.zip"
  (cd "$work/$variant/dex" && "$tools/dexdump" -n -d classes.dex) \
    > "security/$variant.disassembly.txt" 2> /dev/null
}

# Adds DEX files to an APK deterministically: (name, file) pairs.
add_dex() { # apk, then name file pairs
  apk="$1"
  shift
  python3 -I - "$apk" "$@" <<'PY'
import sys, zipfile
apk, rest = sys.argv[1], sys.argv[2:]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as archive:
    for name, path in zip(rest[::2], rest[1::2]):
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, open(path, "rb").read())
PY
}

build positive security/AndroidManifest.xml 16
build clean security/AndroidManifest-clean.xml 24
cp "$work/positive/app.apk" security.apk
add_dex security.apk classes.dex "$work/positive/dex/classes.dex"
cp "$work/clean/app.apk" security-clean.apk
add_dex security-clean.apk classes.dex "$work/clean/dex/classes.dex"
# The positive code cut to its first 60%: its header promises more than the file holds.
python3 -I - "$work/positive/dex/classes.dex" "$work/truncated.dex" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
open(sys.argv[2], "wb").write(data[: len(data) * 6 // 10])
PY
cp "$work/clean/app.apk" security-incomplete.apk
add_dex security-incomplete.apk classes.dex "$work/clean/dex/classes.dex" \
  classes2.dex "$work/truncated.dex"
