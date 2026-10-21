//! Purpose strings: the `Info.plist` texts iOS shows when an app asks for a protected resource
//! (camera, contacts, location...). Without the right key the request fails and the app may be
//! terminated, and App Store Connect flags the build (ITMS-90683, "Missing purpose string in
//! Info.plist") when its code references an API that accesses such a resource, or it holds an
//! entitlement for one, whether the app's own code or a third-party SDK makes the reference.
//!
//! Sources, read on 2026-10-21 (Apple's documentation, through its JSON data endpoints):
//! - `uikit/requesting-access-to-protected-resources`: purpose strings are required for the
//!   resources an app's code references, SDKs included; ITMS-90683 is the example message; a
//!   purpose string has the type its key requires (a string), is not blank or only whitespace,
//!   is shorter than 4,000 bytes, and these rules hold for localized purpose strings too
//!   (`InfoPlist.strings`, checked by [`localized_problems`]);
//! - `bundleresources/protected-resources` and each key's page;
//! - the framework articles naming each resource's APIs: AVFoundation (capture), AVFAudio
//!   (`requestRecordPermission`), PhotoKit, Core Location, Contacts, EventKit (iOS 17 keys),
//!   Core Bluetooth, Core Motion (`NSMotionUsageDescription`'s classes), Speech,
//!   LocalAuthentication, HealthKit, StoreKit and MediaPlayer (media library), HomeKit, Core
//!   NFC, AppTrackingTransparency, SiriKit.
//!
//! Apple does not say which references App Store Connect looks for. msec looks for what a
//! compiler leaves when code uses each resource's gatekeeper: the Objective-C class reference
//! (Swift's uses of these classes leave the same one), with the method that requests access
//! where the class also serves uses that need no permission (`EKEventStore` backs the event
//! editor, which needs none on iOS 17), and C functions and constants by their imports. A
//! method name is weaker evidence (the app may define a method of that name). Code reaching
//! these APIs only through `dlsym` or a string is not seen; the local network (whose prompt
//! comes from network operations, not classes) is not checked.
//!
//! Where several keys satisfy a requirement (full or add-only photo access; the iOS 17
//! calendar keys and their predecessors), any one of them is accepted: which access the code
//! asks for is not visible statically.

use crate::macho::MachO;
use crate::plist::Value;

/// A protected resource and what shows that code uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    /// The resource, in words (`the camera`).
    pub resource: &'static str,
    /// The keys that satisfy it; the first is the one to add.
    pub keys: &'static [&'static str],
    /// What shows the code uses it.
    pub signals: &'static [Signal],
}

/// Evidence that code uses a protected resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Every one of these symbols is imported.
    Imports(&'static [&'static str]),
    /// The class (its `_OBJC_CLASS_$_` symbol) is imported and the method name appears in
    /// `__objc_methname`.
    ClassAndSelector(&'static str, &'static str),
    /// The entitlement is granted (true, or a non-empty value).
    Entitlement(&'static str),
}

/// Every requirement msec checks, in Apple's order of the protected-resources index where it
/// has one.
pub const REQUIREMENTS: [Requirement; 21] = [
    Requirement {
        resource: "the camera",
        keys: &["NSCameraUsageDescription"],
        signals: &[Signal::Imports(&[
            "_OBJC_CLASS_$_AVCaptureDevice",
            "_AVMediaTypeVideo",
        ])],
    },
    Requirement {
        resource: "the microphone",
        keys: &["NSMicrophoneUsageDescription"],
        signals: &[
            Signal::Imports(&["_OBJC_CLASS_$_AVAudioRecorder"]),
            Signal::Imports(&["_OBJC_CLASS_$_AVCaptureDevice", "_AVMediaTypeAudio"]),
            Signal::ClassAndSelector("_OBJC_CLASS_$_AVAudioSession", "requestRecordPermission:"),
            Signal::ClassAndSelector(
                "_OBJC_CLASS_$_AVAudioApplication",
                "requestRecordPermissionWithCompletionHandler:",
            ),
        ],
    },
    Requirement {
        resource: "the photo library",
        keys: &[
            "NSPhotoLibraryUsageDescription",
            "NSPhotoLibraryAddUsageDescription",
        ],
        signals: &[
            Signal::ClassAndSelector("_OBJC_CLASS_$_PHPhotoLibrary", "requestAuthorization:"),
            Signal::ClassAndSelector(
                "_OBJC_CLASS_$_PHPhotoLibrary",
                "requestAuthorizationForAccessLevel:handler:",
            ),
        ],
    },
    Requirement {
        resource: "adding to the photo library",
        keys: &[
            "NSPhotoLibraryAddUsageDescription",
            "NSPhotoLibraryUsageDescription",
        ],
        signals: &[
            Signal::Imports(&["_UIImageWriteToSavedPhotosAlbum"]),
            Signal::Imports(&["_UISaveVideoAtPathToSavedPhotosAlbum"]),
        ],
    },
    Requirement {
        resource: "location while the app is in use",
        keys: &["NSLocationWhenInUseUsageDescription"],
        signals: &[
            Signal::ClassAndSelector(
                "_OBJC_CLASS_$_CLLocationManager",
                "requestWhenInUseAuthorization",
            ),
            // An Always request needs the when-in-use key too.
            Signal::ClassAndSelector(
                "_OBJC_CLASS_$_CLLocationManager",
                "requestAlwaysAuthorization",
            ),
        ],
    },
    Requirement {
        resource: "location at all times",
        keys: &["NSLocationAlwaysAndWhenInUseUsageDescription"],
        signals: &[Signal::ClassAndSelector(
            "_OBJC_CLASS_$_CLLocationManager",
            "requestAlwaysAuthorization",
        )],
    },
    Requirement {
        resource: "contacts",
        keys: &["NSContactsUsageDescription"],
        signals: &[Signal::Imports(&["_OBJC_CLASS_$_CNContactStore"])],
    },
    Requirement {
        resource: "full access to calendars",
        keys: &["NSCalendarsFullAccessUsageDescription"],
        signals: &[Signal::ClassAndSelector(
            "_OBJC_CLASS_$_EKEventStore",
            "requestFullAccessToEventsWithCompletion:",
        )],
    },
    Requirement {
        resource: "adding calendar events",
        keys: &[
            "NSCalendarsWriteOnlyAccessUsageDescription",
            "NSCalendarsFullAccessUsageDescription",
        ],
        signals: &[Signal::ClassAndSelector(
            "_OBJC_CLASS_$_EKEventStore",
            "requestWriteOnlyAccessToEventsWithCompletion:",
        )],
    },
    Requirement {
        resource: "reminders",
        keys: &["NSRemindersFullAccessUsageDescription"],
        signals: &[Signal::ClassAndSelector(
            "_OBJC_CLASS_$_EKEventStore",
            "requestFullAccessToRemindersWithCompletion:",
        )],
    },
    Requirement {
        resource: "calendars or reminders",
        keys: &[
            "NSCalendarsFullAccessUsageDescription",
            "NSCalendarsWriteOnlyAccessUsageDescription",
            "NSCalendarsUsageDescription",
            "NSRemindersFullAccessUsageDescription",
            "NSRemindersUsageDescription",
        ],
        signals: &[Signal::ClassAndSelector(
            "_OBJC_CLASS_$_EKEventStore",
            "requestAccessToEntityType:completion:",
        )],
    },
    Requirement {
        resource: "Bluetooth",
        keys: &["NSBluetoothAlwaysUsageDescription"],
        signals: &[
            Signal::Imports(&["_OBJC_CLASS_$_CBCentralManager"]),
            Signal::Imports(&["_OBJC_CLASS_$_CBPeripheralManager"]),
        ],
    },
    Requirement {
        resource: "motion and fitness data",
        keys: &["NSMotionUsageDescription"],
        signals: &[
            Signal::Imports(&["_OBJC_CLASS_$_CMPedometer"]),
            Signal::Imports(&["_OBJC_CLASS_$_CMMotionActivityManager"]),
            Signal::Imports(&["_OBJC_CLASS_$_CMSensorRecorder"]),
        ],
    },
    Requirement {
        resource: "speech recognition",
        keys: &["NSSpeechRecognitionUsageDescription"],
        signals: &[Signal::Imports(&["_OBJC_CLASS_$_SFSpeechRecognizer"])],
    },
    Requirement {
        resource: "Face ID",
        keys: &["NSFaceIDUsageDescription"],
        signals: &[Signal::ClassAndSelector(
            "_OBJC_CLASS_$_LAContext",
            "evaluatePolicy:localizedReason:reply:",
        )],
    },
    Requirement {
        resource: "health data",
        keys: &[
            "NSHealthShareUsageDescription",
            "NSHealthUpdateUsageDescription",
        ],
        signals: &[
            Signal::ClassAndSelector(
                "_OBJC_CLASS_$_HKHealthStore",
                "requestAuthorizationToShareTypes:readTypes:completion:",
            ),
            Signal::Entitlement("com.apple.developer.healthkit"),
        ],
    },
    Requirement {
        resource: "the media library",
        keys: &["NSAppleMusicUsageDescription"],
        signals: &[
            Signal::Imports(&["_OBJC_CLASS_$_MPMediaQuery"]),
            Signal::ClassAndSelector("_OBJC_CLASS_$_MPMediaLibrary", "requestAuthorization:"),
            Signal::ClassAndSelector(
                "_OBJC_CLASS_$_SKCloudServiceController",
                "requestAuthorization:",
            ),
        ],
    },
    Requirement {
        resource: "HomeKit",
        keys: &["NSHomeKitUsageDescription"],
        signals: &[
            Signal::Imports(&["_OBJC_CLASS_$_HMHomeManager"]),
            Signal::Entitlement("com.apple.developer.homekit"),
        ],
    },
    Requirement {
        resource: "the NFC reader",
        keys: &["NFCReaderUsageDescription"],
        signals: &[
            Signal::Imports(&["_OBJC_CLASS_$_NFCNDEFReaderSession"]),
            Signal::Imports(&["_OBJC_CLASS_$_NFCTagReaderSession"]),
            Signal::Imports(&["_OBJC_CLASS_$_NFCVASReaderSession"]),
            Signal::Entitlement("com.apple.developer.nfc.readersession.formats"),
        ],
    },
    Requirement {
        resource: "tracking (App Tracking Transparency)",
        keys: &["NSUserTrackingUsageDescription"],
        signals: &[Signal::ClassAndSelector(
            "_OBJC_CLASS_$_ATTrackingManager",
            "requestTrackingAuthorizationWithCompletionHandler:",
        )],
    },
    Requirement {
        resource: "Siri",
        keys: &["NSSiriUsageDescription"],
        signals: &[
            Signal::ClassAndSelector("_OBJC_CLASS_$_INPreferences", "requestSiriAuthorization:"),
            Signal::Entitlement("com.apple.developer.siri"),
        ],
    },
];

/// Code that uses a protected resource: the requirement (an index into [`REQUIREMENTS`]) and
/// the evidence (`import _OBJC_CLASS_$_CNContactStore`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceUse {
    /// Index into [`REQUIREMENTS`].
    pub requirement: usize,
    /// What was seen.
    pub evidence: String,
    /// The evidence includes a method name (weaker: the app may define a method of that name).
    pub by_selector: bool,
}

impl ResourceUse {
    /// The requirement.
    pub fn requirement(&self) -> &'static Requirement {
        &REQUIREMENTS[self.requirement]
    }
}

/// The protected resources one image's code uses, by imports and by the method names in
/// `methnames` (`__objc_methname`; `None` when not read). Entitlements are checked by
/// [`entitlement_uses`]. One use per requirement: the first signal that matches.
pub fn uses_in(image: &MachO, methnames: Option<&[u8]>) -> Vec<ResourceUse> {
    let selectors: Vec<&[u8]> = methnames
        .map(|bytes| bytes.split(|byte| *byte == 0).collect())
        .unwrap_or_default();
    let mut found = Vec::new();
    for (index, requirement) in REQUIREMENTS.iter().enumerate() {
        let used = requirement.signals.iter().find_map(|signal| match signal {
            Signal::Imports(symbols) => symbols
                .iter()
                .all(|symbol| image.imports(symbol))
                .then(|| (format!("import {}", symbols.join(", import ")), false)),
            Signal::ClassAndSelector(class, selector) => (image.imports(class)
                && selectors.contains(&selector.as_bytes()))
            .then(|| (format!("import {class}, selector {selector}"), true)),
            Signal::Entitlement(_) => None,
        });
        if let Some((evidence, by_selector)) = used {
            found.push(ResourceUse {
                requirement: index,
                evidence,
                by_selector,
            });
        }
    }
    found
}

/// The protected resources an executable's entitlements grant access to.
pub fn entitlement_uses(entitlements: &crate::plist::Dictionary) -> Vec<ResourceUse> {
    let mut found = Vec::new();
    for (index, requirement) in REQUIREMENTS.iter().enumerate() {
        let granted = requirement.signals.iter().find_map(|signal| match signal {
            Signal::Entitlement(key) => entitlements
                .get(key)
                .filter(|value| granted(value))
                .map(|_| format!("entitlement {key}")),
            _ => None,
        });
        if let Some(evidence) = granted {
            found.push(ResourceUse {
                requirement: index,
                evidence,
                by_selector: false,
            });
        }
    }
    found
}

/// An entitlement grants something when it is true or a non-empty value.
fn granted(value: &Value) -> bool {
    match value {
        Value::Boolean(flag) => *flag,
        Value::Array(items) => !items.is_empty(),
        Value::String(text) => !text.is_empty(),
        Value::Dictionary(entries) => !entries.is_empty(),
        _ => true,
    }
}

/// Apple: "The purpose string is shorter than 4,000 bytes."
pub const MAX_PURPOSE_STRING_BYTES: usize = 4000;

/// What is wrong with one purpose string's text for `resource`: blank (or only whitespace), or
/// 4,000 bytes or longer; `None` when it is usable.
fn text_problem(key: &str, text: &str, resource: &str) -> Option<String> {
    if text.trim().is_empty() {
        return Some(format!(
            "{key} is empty: a purpose string must say why the app needs {resource}"
        ));
    }
    if text.len() >= MAX_PURPOSE_STRING_BYTES {
        return Some(format!(
            "{key} is {} bytes: a purpose string must be shorter than 4,000 bytes",
            thousands(text.len())
        ));
    }
    None
}

/// `4123` as `4,123`.
fn thousands(number: usize) -> String {
    let digits = number.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// What is wrong with a bundle's purpose string for one requirement; `None` when one of its
/// keys holds a usable text (a non-blank string shorter than 4,000 bytes). `descriptions` is
/// the bundle's `usage_descriptions`; `wrong_types` its keys of the wrong type. A localization
/// does not stand in for the base value, which iOS falls back to.
pub fn purpose_problem(
    requirement: &Requirement,
    descriptions: &[(String, String)],
    wrong_types: &[super::WrongType],
) -> Option<String> {
    let text_of = |key: &str| {
        descriptions
            .iter()
            .find(|(named, _)| named == key)
            .map(|(_, text)| text.as_str())
    };
    if requirement.keys.iter().any(|key| {
        text_of(key).is_some_and(|text| text_problem(key, text, requirement.resource).is_none())
    }) {
        return None;
    }
    let first = requirement.keys[0];
    let others = if requirement.keys.len() > 1 {
        format!(" (or {})", requirement.keys[1..].join(", "))
    } else {
        String::new()
    };
    if let Some(wrong) = requirement
        .keys
        .iter()
        .find_map(|key| wrong_types.iter().find(|wrong| wrong.key == *key))
    {
        return Some(format!(
            "{} is not a string ({}): iOS has no purpose string to show",
            wrong.key, wrong.found
        ));
    }
    if let Some((key, text)) = requirement
        .keys
        .iter()
        .find_map(|key| text_of(key).map(|text| (*key, text)))
    {
        return text_problem(key, text, requirement.resource);
    }
    Some(format!("Info.plist has no {first}{others}"))
}

/// What is wrong with a localization's values for `requirement`'s keys (`InfoPlist.strings`):
/// Apple's rules hold for localized purpose strings too, so each key the localization sets
/// must be a usable purpose string. A key it does not set falls back to `Info.plist`.
pub fn localized_problems(
    requirement: &Requirement,
    strings: &crate::plist::Dictionary,
) -> Vec<(&'static str, String)> {
    requirement
        .keys
        .iter()
        .filter_map(|key| {
            let value = strings.get(key)?;
            let problem = match value.as_str() {
                None => Some(format!(
                    "{key} is not a string ({}): iOS has no purpose string to show",
                    value.type_name()
                )),
                Some(text) => text_problem(key, text, requirement.resource),
            };
            problem.map(|problem| (*key, problem))
        })
        .collect()
}
