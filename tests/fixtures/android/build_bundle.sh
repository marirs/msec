#!/bin/sh
# Rebuilds the app bundle fixtures and the protobuf manifests of the APK fixtures:
# - bundle.aab: modules base (with dex/v035.dex as classes.dex and native/libapp.so), camera
#   (an on-demand feature module declaring its own activity and permission) and textures (a
#   fast-follow asset pack); bundle-base.aab: the base module alone. Manifests and resource
#   tables come from `aapt2 link --proto-format`, as in Android's command-line build; the
#   bundle layout and BundleConfig.pb from bundle/make_bundle.py (bundletool is not used).
#   Both are signed with jarsigner and a fresh upload key each run (tests check structure, not
#   key values).
# - proto/<fixture>.AndroidManifest.pb, proto/<fixture>.resources.pb and
#   proto/<fixture>.xmltree.txt: each APK fixture's manifest and resource table linked in
#   protobuf format, and aapt2's dump of the manifest; the tests compare msec's protobuf
#   decoding against the dump and against the binary APK built from the same sources.
# - bundle/bundletool.txt, bundle/base-master.apk, bundle/camera-master.apk: Google's bundletool
#   validates both bundles and builds their APKs (signed with the fixture key); its report and the
#   APK list are kept as evidence that the bundles are valid, and two of the APKs it builds (binary
#   manifests bundletool converted from the bundles' protobuf ones) are what the tests compare
#   msec's protobuf decoding against.
# Needs ANDROID_HOME (or the default macOS SDK location), build-tools 37.0.0, platform
# android-37.0, a JDK (keytool and jarsigner on PATH, or JAVA_HOME), and bundletool: the
# command in BUNDLETOOL, else `bundletool` on PATH (Homebrew's bundletool, or
# `java -jar bundletool-all-<version>.jar`).
set -eu
cd "$(dirname "$0")"
sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
aapt2="$sdk/build-tools/37.0.0/aapt2"
platform="$sdk/platforms/android-37.0/android.jar"
if [ -n "${JAVA_HOME:-}" ]; then PATH="$JAVA_HOME/bin:$PATH"; fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

link_proto() { # manifest, output zip, [resource directory]
  if [ -n "${3:-}" ]; then
    "$aapt2" compile --dir "$3" -o "$work/res-$$.zip"
    "$aapt2" link --proto-format -I "$platform" --manifest "$1" -o "$2" "$work/res-$$.zip"
    rm "$work/res-$$.zip"
  else
    "$aapt2" link --proto-format -I "$platform" --manifest "$1" -o "$2"
  fi
}

link_proto bundle/base/AndroidManifest.xml "$work/base.zip" bundle/base/res
link_proto bundle/camera/AndroidManifest.xml "$work/camera.zip"
link_proto bundle/textures/AndroidManifest.xml "$work/textures.zip"
python3 -I bundle/make_bundle.py "$work" dex/v035.dex native/libapp.so .
keytool -genkeypair -keystore "$work/upload.jks" -storepass fixture -keypass fixture \
  -alias upload -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=msec fixture upload key" \
  -noprompt > /dev/null 2>&1
for bundle in bundle.aab bundle-base.aab; do
  jarsigner -keystore "$work/upload.jks" -storepass fixture -keypass fixture \
    -sigalg SHA256withRSA -digestalg SHA-256 "$bundle" upload > /dev/null
done
bundletool="${BUNDLETOOL:-bundletool}"
{
  echo "bundletool $($bundletool version)"
  for bundle in bundle bundle-base; do
    echo "== $bundle.aab: bundletool validate"
    $bundletool validate --bundle="$bundle.aab" > "$work/validate.txt"
    sed -n '/^Feature modules:/,$p' "$work/validate.txt"
    $bundletool build-apks --bundle="$bundle.aab" --output="$work/$bundle.apks" \
      --aapt2="$aapt2" --ks="$work/upload.jks" --ks-pass=pass:fixture --ks-key-alias=upload \
      --key-pass=pass:fixture > /dev/null
    echo "== $bundle.aab: bundletool build-apks"
    unzip -Z1 "$work/$bundle.apks" | sort
  done
} > bundle/bundletool.txt
unzip -p "$work/bundle.apks" splits/base-master.apk > bundle/base-master.apk
unzip -p "$work/bundle.apks" splits/camera-master.apk > bundle/camera-master.apk

for module in base camera textures; do
  "$aapt2" dump xmltree --file AndroidManifest.xml "$work/$module.zip" > "bundle/$module.xmltree.txt"
done

mkdir -p proto
for fixture in basic risky network store code; do
  link_proto "$fixture/AndroidManifest.xml" "$work/$fixture.zip" "$fixture/res"
  unzip -p "$work/$fixture.zip" AndroidManifest.xml > "proto/$fixture.AndroidManifest.pb"
  unzip -p "$work/$fixture.zip" resources.pb > "proto/$fixture.resources.pb"
  "$aapt2" dump xmltree --file AndroidManifest.xml "$work/$fixture.zip" > "proto/$fixture.xmltree.txt"
done
