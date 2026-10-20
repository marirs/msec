#!/bin/sh
# Rebuilds the DEX fixtures:
# - dex/v0NN.dex: d8's output for code/java/primary in each DEX version d8 writes (041 is the
#   experimental container format, behind a D8 system property); dex/r8.dex: R8's shrunk and
#   obfuscated output for the same classes;
# - code.apk: the code/ app with classes.dex (code/java/primary) and classes2.dex
#   (code/java/secondary); code/java/stubs declares removed framework APIs for javac only;
# - dex/container.dex and dex/hostile/*.dex: synthetic files from make_dex_fixtures.py;
# - dex/**/*.dexdump.txt, dex/*.disassembly.txt and dex/art-verdicts.txt: what AOSP's dexdump
#   (ART's DEX loader and verifier) reads in each file, its disassembly, and whether it accepts
#   each hostile file. The tests compare msec against these.
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

compile() { # source directory, output directory
  mkdir -p "$2"
  find "$1" -name '*.java' | sort > "$work/sources"
  # The stubs come first on the class path: they declare APIs Android removed from android.jar,
  # so the fixture can call them. Their classes are not in "$2" and are never dexed.
  javac --release 8 -nowarn -Xlint:-options -encoding UTF-8 -cp "$work/stubs:$platform" -d "$2" \
    @"$work/sources"
  find "$2" -name '*.class' | sort > "$2.list"
}
dex() { # min API, class list, output directory, extra D8 JVM flags...
  api="$1" list="$2" output="$3"
  shift 3
  mkdir -p "$output"
  java "$@" -cp "$tools/lib/d8.jar" com.android.tools.r8.D8 --release --lib "$platform" \
    --min-api "$api" --output "$output" $(cat "$list")
}

mkdir -p "$work/stubs"
javac --release 8 -nowarn -Xlint:-options -encoding UTF-8 -d "$work/stubs" \
  $(find code/java/stubs -name '*.java' | sort)
compile code/java/primary "$work/primary"
compile code/java/secondary "$work/secondary"
for pair in 21:035 24:037 26:038 28:039; do
  dex "${pair%:*}" "$work/primary.list" "$work/api${pair%:*}"
  cp "$work/api${pair%:*}/classes.dex" "dex/v${pair#*:}.dex"
done
dex 36 "$work/primary.list" "$work/api36" -Dcom.android.tools.r8.dexContainerExperiment=true
cp "$work/api36/classes.dex" dex/v041.dex
dex 21 "$work/secondary.list" "$work/secondary-dex"
# The same code shrunk and obfuscated by R8 (keeping the activity), as release builds are.
printf '%s\n' '-keep class dev.appchk.fixture.code.MainActivity { *; }' '-dontwarn **' > "$work/keep.pro"
mkdir -p "$work/r8"
java -cp "$tools/lib/d8.jar" com.android.tools.r8.R8 --release --lib "$platform" --min-api 21 \
  --pg-conf "$work/keep.pro" --output "$work/r8" $(cat "$work/primary.list")
cp "$work/r8/classes.dex" dex/r8.dex

"$tools/aapt2" compile --dir code/res -o "$work/res.zip"
"$tools/aapt2" link -I "$platform" --manifest code/AndroidManifest.xml -o code.apk "$work/res.zip"
python3 -I - code.apk dex/v035.dex "$work/secondary-dex/classes.dex" <<'EOF'
import sys, zipfile
apk, primary, secondary = sys.argv[1:]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as archive:
    for name, path in (("classes.dex", primary), ("classes2.dex", secondary)):
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, open(path, "rb").read())
EOF
"$tools/aapt2" dump xmltree --file AndroidManifest.xml code.apk > code.xmltree.txt

python3 -I dex/make_dex_fixtures.py dex/v035.dex dex

# dexdump's view: headers and classes (-f, -n: no debug info) and the string table (-s), run
# from the file's directory so the output names no absolute path. Its log lines carry a
# timestamp and process id; only the message after "dexdump : <source>:<line> " is kept.
messages() { sed -n 's/^.* dexdump : [a-z_]*\.cc:[0-9]* //p'; }
(
  cd dex
  for file in v*.dex container.dex r8.dex; do
    "$tools/dexdump" -n -f -s "$file" > "${file%.dex}.dexdump.txt" 2> /dev/null
  done
  # Disassembly (-d): every method's instructions with the method, field and type each
  # references, which the tests compare msec's code scan against.
  for file in v035.dex v039.dex v041.dex; do
    "$tools/dexdump" -n -d "$file" > "${file%.dex}.disassembly.txt" 2> /dev/null
  done
  for file in hostile/*.dex; do
    if "$tools/dexdump" -n "$file" > /dev/null 2> "$work/log"; then
      echo "${file#hostile/}: accepted"
    else
      echo "${file#hostile/}: rejected: $(messages < "$work/log" | grep -v "^Failure to open" | head -n 1 | cut -c 1-160)"
    fi
  done > art-verdicts.txt
)
