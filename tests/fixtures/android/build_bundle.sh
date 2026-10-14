#!/bin/sh
# Rebuilds the app bundle fixtures and the protobuf manifests of the APK fixtures:
# - bundle.aab: modules base (with dex/v035.dex as classes.dex and native/libapp.so), camera
#   (an on-demand feature module declaring its own activity and permission) and textures (a
#   fast-follow asset pack); bundle-base.aab: the base module alone. Manifests and resource
#   tables come from `aapt2 link --proto-format`, as in Android's command-line build; the
#   bundle layout and BundleConfig.pb from bundle/make_bundle.py (bundletool is not used).
#   Both are signed with jarsigner and a fresh upload key each run (tests check structure, not
#   key values).
# - proto/<fixture>.AndroidManifest.pb and proto/<fixture>.xmltree.txt: each APK fixture's
#   manifest linked in protobuf format, and aapt2's dump of it, the oracle the tests compare
#   msec's protobuf decoding against.
# Needs ANDROID_HOME (or the default macOS SDK location), build-tools 37.0.0, platform
# android-37.0, and a JDK (keytool and jarsigner on PATH, or JAVA_HOME).
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
for module in base camera textures; do
  "$aapt2" dump xmltree --file AndroidManifest.xml "$work/$module.zip" > "bundle/$module.xmltree.txt"
done

mkdir -p proto
for fixture in basic risky network store code; do
  link_proto "$fixture/AndroidManifest.xml" "$work/$fixture.zip" "$fixture/res"
  unzip -p "$work/$fixture.zip" AndroidManifest.xml > "proto/$fixture.AndroidManifest.pb"
  "$aapt2" dump xmltree --file AndroidManifest.xml "$work/$fixture.zip" > "proto/$fixture.xmltree.txt"
done
