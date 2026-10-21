#!/bin/sh
# Rebuilds msec's App Store requirements fixture (ipa/store.ipa) and Apple's tools' reading of
# it (store-verdicts.txt). The app (store/) is built for iOS devices with Xcode's clang and
# signed ad hoc:
# - its main executable uses contacts (no purpose string), location while in use (a blank
#   one), the camera (a valid one) and motion data (an integer instead of a string); its
#   entitlements grant HealthKit, without either health purpose string;
# - Lib.framework uses Bluetooth, whose purpose string the app's Info.plist lacks;
# - PlugIns/Share.appex uses speech recognition: the app's Info.plist has that purpose string,
#   the extension's own does not;
# - the privacy manifest declares tracking and nothing references ATTrackingManager;
# - Info.plist records the iOS 25.2 SDK and MinimumOSVersion 12.0 (the code itself is compiled
#   for iOS 17: current SDKs do not target iOS 12), as a build made before 2026 would.
# store-verdicts.txt: per executable, the symbols nm -u lists and the Objective-C selectors
# otool finds that a purpose-string requirement names, and codesign's reading of the
# entitlements.
# Needs macOS with Xcode (an iOS SDK) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
cc="xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot $sdk -Os -fobjc-arc"
app="$work/Fixture.app"
mkdir -p "$app/Frameworks/Lib.framework" "$app/PlugIns/Share.appex"
python3 -I - "$app" <<'PY'
import plistlib
import sys
from pathlib import Path
app = Path(sys.argv[1])
def write(path, content):
    path.write_bytes(plistlib.dumps(content, fmt=plistlib.FMT_BINARY))
common = {"CFBundleInfoDictionaryVersion": "6.0", "CFBundleShortVersionString": "1.0",
          "CFBundleVersion": "1", "MinimumOSVersion": "12.0",
          "CFBundleSupportedPlatforms": ["iPhoneOS"], "DTPlatformName": "iphoneos",
          "DTSDKName": "iphoneos25.2", "DTXcode": "2520"}
write(app / "Info.plist", {**common, "CFBundleIdentifier": "dev.appchk.store",
      "CFBundleExecutable": "Fixture", "CFBundleName": "Store", "CFBundlePackageType": "APPL",
      "UIDeviceFamily": [1], "LSRequiresIPhoneOS": True,
      "NSCameraUsageDescription": "Scans documents you choose to add.",
      "NSLocationWhenInUseUsageDescription": "  ",
      "NSMotionUsageDescription": 1,
      "NSSpeechRecognitionUsageDescription": "Turns your dictation into notes."})
write(app / "Frameworks/Lib.framework/Info.plist", {**common,
      "CFBundleIdentifier": "dev.appchk.store.lib", "CFBundleExecutable": "Lib",
      "CFBundlePackageType": "FMWK"})
write(app / "PlugIns/Share.appex/Info.plist", {**common,
      "CFBundleIdentifier": "dev.appchk.store.share", "CFBundleExecutable": "Share",
      "CFBundleName": "Share", "CFBundlePackageType": "XPC!",
      "NSExtension": {"NSExtensionPointIdentifier": "com.apple.share-services",
                      "NSExtensionPrincipalClass": "ShareViewController"}})
PY
$cc -dynamiclib -install_name @rpath/Lib.framework/Lib -framework CoreBluetooth \
  -o "$app/Frameworks/Lib.framework/Lib" store/Lib/lib.m
$cc -framework Foundation -framework Speech -o "$app/PlugIns/Share.appex/Share" \
  store/Share/share.m
$cc -framework Foundation -framework AVFoundation -framework Contacts -framework CoreLocation \
  -framework CoreMotion -Wl,-rpath,@executable_path/Frameworks -o "$app/Fixture" store/main.m
cp store/PrivacyInfo.xcprivacy "$app/PrivacyInfo.xcprivacy"
codesign -s - -f --timestamp=none "$app/Frameworks/Lib.framework" > /dev/null 2>&1
codesign -s - -f --timestamp=none "$app/PlugIns/Share.appex" > /dev/null 2>&1
codesign -s - -f --timestamp=none --entitlements store/entitlements.plist "$app" > /dev/null 2>&1
python3 -I make_ipa.py ipa ipa/store.ipa payload "$app"

# What the executables reference, as Apple's tools list it: the imported symbols (nm -u) and
# Objective-C selectors (otool) a requirement in src/ios/purpose_strings.rs names, and the
# entitlements codesign reads.
symbols='AVCaptureDevice|AVMediaTypeVideo|AVMediaTypeAudio|AVAudioRecorder|AVAudioSession|AVAudioApplication|PHPhotoLibrary|UIImageWriteToSavedPhotosAlbum|UISaveVideoAtPathToSavedPhotosAlbum|CLLocationManager|CNContactStore|EKEventStore|CBCentralManager|CBPeripheralManager|CMPedometer|CMMotionActivityManager|CMSensorRecorder|SFSpeechRecognizer|LAContext|HKHealthStore|MPMediaQuery|MPMediaLibrary|SKCloudServiceController|HMHomeManager|NFCNDEFReaderSession|NFCTagReaderSession|NFCVASReaderSession|ATTrackingManager|INPreferences'
selectors='requestRecordPermission:|requestRecordPermissionWithCompletionHandler:|requestAuthorization:|requestAuthorizationForAccessLevel:handler:|requestWhenInUseAuthorization|requestAlwaysAuthorization|requestFullAccessToEventsWithCompletion:|requestWriteOnlyAccessToEventsWithCompletion:|requestFullAccessToRemindersWithCompletion:|requestAccessToEntityType:completion:|evaluatePolicy:localizedReason:reply:|requestAuthorizationToShareTypes:readTypes:completion:|requestTrackingAuthorizationWithCompletionHandler:|requestSiriAuthorization:'
{
  for binary in Fixture Frameworks/Lib.framework/Lib PlugIns/Share.appex/Share; do
    echo "$binary:"
    xcrun nm -u "$app/$binary" | sed -E 's/^_//; s/^OBJC_CLASS_\$_//' \
      | grep -E "^($symbols)$" | sed 's/^/  import /' || true
    xcrun otool -v -s __TEXT __objc_methname "$app/$binary" 2> /dev/null | tr ' \t' '\n\n' \
      | grep -E "^($selectors)$" | sort -u | sed 's/^/  selector /' || true
    codesign -d --entitlements - --xml "$app/$binary" 2> /dev/null \
      | plutil -convert json -o - - 2> /dev/null \
      | python3 -I -c 'import json, sys
text = sys.stdin.read()
for key, value in sorted(json.loads(text).items() if text.strip() else []):
    if value:
        print("  entitlement " + key)'

  done
} > store-verdicts.txt
