#!/bin/sh
# Rebuilds msec's privacy fixture (ipa/privacy.ipa) and the oracles' reading of it
# (privacy-verdicts.txt). The app (privacy/) is built for iOS devices with Xcode's clang and
# signed ad hoc:
# - its main executable uses one API of each required-reason category (stat, mach_absolute_time
#   and systemUptime, statfs and NSFileSystemFreeSize, activeInputModes, NSUserDefaults);
#   its privacy manifest declares file timestamps and user defaults with approved reasons,
#   system boot time with a reason code Apple does not define, and a collected data type
#   Apple does not define, and leaves disk space and active keyboards undeclared;
# - Lib.framework calls fstat, and its own manifest declares no API use;
# - Alamofire.framework, named like an SDK on Apple's list of commonly used third-party SDKs,
#   ships no privacy manifest (it is not Alamofire).
# privacy-verdicts.txt: per executable, the symbols nm -u lists and the Objective-C selectors
# strings finds that name a required-reason API, and plutil -lint's verdict on each manifest.
# Needs macOS with Xcode (an iOS SDK) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
cc="xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot $sdk -Os"
app="$work/Fixture.app"
mkdir -p "$app/Frameworks/Lib.framework" "$app/Frameworks/Alamofire.framework"
python3 -I - "$app" <<'PY'
import plistlib
import sys
from pathlib import Path
app = Path(sys.argv[1])
def write(path, content):
    path.write_bytes(plistlib.dumps(content, fmt=plistlib.FMT_BINARY))
common = {"CFBundleInfoDictionaryVersion": "6.0", "CFBundleShortVersionString": "1.0",
          "CFBundleVersion": "1", "MinimumOSVersion": "17.0",
          "CFBundleSupportedPlatforms": ["iPhoneOS"]}
write(app / "Info.plist", {**common, "CFBundleIdentifier": "dev.appchk.privacy",
      "CFBundleExecutable": "Fixture", "CFBundleName": "Privacy", "CFBundlePackageType": "APPL",
      "UIDeviceFamily": [1], "LSRequiresIPhoneOS": True})
write(app / "Frameworks/Lib.framework/Info.plist", {**common,
      "CFBundleIdentifier": "dev.appchk.privacy.lib", "CFBundleExecutable": "Lib",
      "CFBundlePackageType": "FMWK"})
write(app / "Frameworks/Alamofire.framework/Info.plist", {**common,
      "CFBundleIdentifier": "org.alamofire.Alamofire", "CFBundleExecutable": "Alamofire",
      "CFBundlePackageType": "FMWK"})
PY
$cc -dynamiclib -install_name @rpath/Lib.framework/Lib -o "$app/Frameworks/Lib.framework/Lib" \
  privacy/Lib/lib.c
cp privacy/Lib/PrivacyInfo.xcprivacy "$app/Frameworks/Lib.framework/PrivacyInfo.xcprivacy"
$cc -dynamiclib -install_name @rpath/Alamofire.framework/Alamofire \
  -o "$app/Frameworks/Alamofire.framework/Alamofire" privacy/Alamofire/alamofire.c
$cc -fobjc-arc -framework Foundation -framework UIKit -Wl,-rpath,@executable_path/Frameworks \
  -o "$app/Fixture" privacy/main.m
cp privacy/PrivacyInfo.xcprivacy "$app/PrivacyInfo.xcprivacy"
codesign -s - -f --timestamp=none "$app/Frameworks/Lib.framework" > /dev/null 2>&1
codesign -s - -f --timestamp=none "$app/Frameworks/Alamofire.framework" > /dev/null 2>&1
codesign -s - -f --timestamp=none "$app" > /dev/null 2>&1
python3 -I make_ipa.py ipa ipa/privacy.ipa payload "$app"

# What the binaries reference, as Apple's tools list it: imported symbols (nm -u) and the
# Objective-C selectors in __objc_methname (strings), filtered to required-reason API names.
apis='stat|fstat|lstat|fstatat|getattrlist|getattrlistbulk|fgetattrlist|getattrlistat|statfs|statvfs|fstatfs|fstatvfs|mach_absolute_time|NSFileSystemFreeSize|NSFileSystemSize|NSUserDefaults|systemUptime|activeInputModes|creationDate|modificationDate|fileModificationDate|NSFileCreationDate|NSFileModificationDate|NSURL[A-Za-z]*Key'
{
  for binary in Fixture Frameworks/Lib.framework/Lib Frameworks/Alamofire.framework/Alamofire; do
    echo "$binary:"
    xcrun nm -u "$app/$binary" | sed -E 's/^_//; s/^OBJC_CLASS_\$_//' | grep -E "^($apis)$" \
      | sed 's/^/  import /' || true
    xcrun otool -v -s __TEXT __objc_methname "$app/$binary" 2> /dev/null | tr ' \t' '\n\n' \
      | grep -E "^($apis)$" | sort -u | sed 's/^/  selector /' || true
  done
  for manifest in PrivacyInfo.xcprivacy Frameworks/Lib.framework/PrivacyInfo.xcprivacy; do
    echo "$manifest: $(plutil -lint "$app/$manifest" | sed "s|$app/||")"
  done
} > privacy-verdicts.txt
