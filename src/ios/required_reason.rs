//! Apple's privacy-manifest reference data and what an executable shows of it: the
//! required-reason API categories with the APIs and approved reason codes of each, the values
//! a manifest's collected-data entries may take, and the commonly used third-party SDKs that
//! must ship their own manifest.
//!
//! Sources, read on 2026-10-21 (Apple's documentation, through its JSON data endpoints):
//! - `bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype`
//!   and `.../nsprivacyaccessedapitypereasons`: the five categories, their APIs (in Apple's
//!   order) and the 17 reason codes;
//! - `.../nsprivacycollecteddatatypes/nsprivacycollecteddatatype` and
//!   `.../nsprivacycollecteddatatypepurposes`: 35 data types and 6 purposes;
//! - TN3181 (debugging an invalid privacy manifest): what makes a manifest invalid;
//! - <https://developer.apple.com/support/third-party-SDK-requirements/>: 86 SDKs.
//!
//! Apple does not say how App Store Connect finds these APIs in a binary. msec looks for what
//! a compiler leaves: imported symbols for C functions and Foundation constants
//! (`_stat`, `_NSFileSystemFreeSize`), the Objective-C class reference for `NSUserDefaults`
//! (Swift's `UserDefaults` is the same class), and Objective-C method names in
//! `__objc_methname` for methods (`systemUptime`, `activeInputModes`, `fileModificationDate`).
//! A method name is weaker evidence (the app may define a method of that name); each use says
//! which it is. Code that calls these APIs only through `dlsym` or a string is not seen.

use crate::macho::MachO;

/// A required-reason API category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// `NSPrivacyAccessedAPICategoryFileTimestamp`.
    FileTimestamp,
    /// `NSPrivacyAccessedAPICategorySystemBootTime`.
    SystemBootTime,
    /// `NSPrivacyAccessedAPICategoryDiskSpace`.
    DiskSpace,
    /// `NSPrivacyAccessedAPICategoryActiveKeyboards`.
    ActiveKeyboards,
    /// `NSPrivacyAccessedAPICategoryUserDefaults`.
    UserDefaults,
}

impl Category {
    /// Every category, in Apple's order.
    pub const ALL: [Self; 5] = [
        Self::FileTimestamp,
        Self::SystemBootTime,
        Self::DiskSpace,
        Self::ActiveKeyboards,
        Self::UserDefaults,
    ];

    /// The `NSPrivacyAccessedAPIType` value.
    pub fn key(self) -> &'static str {
        match self {
            Self::FileTimestamp => "NSPrivacyAccessedAPICategoryFileTimestamp",
            Self::SystemBootTime => "NSPrivacyAccessedAPICategorySystemBootTime",
            Self::DiskSpace => "NSPrivacyAccessedAPICategoryDiskSpace",
            Self::ActiveKeyboards => "NSPrivacyAccessedAPICategoryActiveKeyboards",
            Self::UserDefaults => "NSPrivacyAccessedAPICategoryUserDefaults",
        }
    }

    /// The category a manifest names.
    pub fn of_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|category| category.key() == key)
    }

    /// The approved reason codes.
    pub fn reasons(self) -> &'static [&'static str] {
        match self {
            Self::FileTimestamp => &["DDA9.1", "C617.1", "3B52.1", "0A2A.1"],
            Self::SystemBootTime => &["35F9.1", "8FFB.1", "3D61.1"],
            Self::DiskSpace => &["85F4.1", "E174.1", "7D9E.1", "B728.1"],
            Self::ActiveKeyboards => &["3EC4.1", "54BD.1"],
            Self::UserDefaults => &["CA92.1", "1C8F.1", "C56D.1", "AC6B.1"],
        }
    }
}

/// How an API shows in a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    /// An imported symbol (`_stat`, `_NSFileSystemFreeSize`, `_OBJC_CLASS_$_NSUserDefaults`).
    Import(&'static str),
    /// An Objective-C method name in `__objc_methname`.
    Selector(&'static str),
}

/// Apple's APIs per category, as Apple names them, with how each shows in a binary.
/// `getattrlist`, `fgetattrlist` and `getattrlistat` are in two categories, as Apple lists
/// them.
const APIS: &[(Category, &str, Signal)] = &[
    (
        Category::FileTimestamp,
        "creationDate",
        Signal::Import("_NSFileCreationDate"),
    ),
    (
        Category::FileTimestamp,
        "modificationDate",
        Signal::Import("_NSFileModificationDate"),
    ),
    (
        Category::FileTimestamp,
        "fileModificationDate",
        Signal::Selector("fileModificationDate"),
    ),
    (
        Category::FileTimestamp,
        "contentModificationDateKey",
        Signal::Import("_NSURLContentModificationDateKey"),
    ),
    (
        Category::FileTimestamp,
        "creationDateKey",
        Signal::Import("_NSURLCreationDateKey"),
    ),
    (
        Category::FileTimestamp,
        "getattrlist",
        Signal::Import("_getattrlist"),
    ),
    (
        Category::FileTimestamp,
        "getattrlistbulk",
        Signal::Import("_getattrlistbulk"),
    ),
    (
        Category::FileTimestamp,
        "fgetattrlist",
        Signal::Import("_fgetattrlist"),
    ),
    (Category::FileTimestamp, "stat", Signal::Import("_stat")),
    (Category::FileTimestamp, "fstat", Signal::Import("_fstat")),
    (
        Category::FileTimestamp,
        "fstatat",
        Signal::Import("_fstatat"),
    ),
    (Category::FileTimestamp, "lstat", Signal::Import("_lstat")),
    (
        Category::FileTimestamp,
        "getattrlistat",
        Signal::Import("_getattrlistat"),
    ),
    (
        Category::SystemBootTime,
        "systemUptime",
        Signal::Selector("systemUptime"),
    ),
    (
        Category::SystemBootTime,
        "mach_absolute_time",
        Signal::Import("_mach_absolute_time"),
    ),
    (
        Category::DiskSpace,
        "volumeAvailableCapacityKey",
        Signal::Import("_NSURLVolumeAvailableCapacityKey"),
    ),
    (
        Category::DiskSpace,
        "volumeAvailableCapacityForImportantUsageKey",
        Signal::Import("_NSURLVolumeAvailableCapacityForImportantUsageKey"),
    ),
    (
        Category::DiskSpace,
        "volumeAvailableCapacityForOpportunisticUsageKey",
        Signal::Import("_NSURLVolumeAvailableCapacityForOpportunisticUsageKey"),
    ),
    (
        Category::DiskSpace,
        "volumeTotalCapacityKey",
        Signal::Import("_NSURLVolumeTotalCapacityKey"),
    ),
    (
        Category::DiskSpace,
        "systemFreeSize",
        Signal::Import("_NSFileSystemFreeSize"),
    ),
    (
        Category::DiskSpace,
        "systemSize",
        Signal::Import("_NSFileSystemSize"),
    ),
    (Category::DiskSpace, "statfs", Signal::Import("_statfs")),
    (Category::DiskSpace, "statvfs", Signal::Import("_statvfs")),
    (Category::DiskSpace, "fstatfs", Signal::Import("_fstatfs")),
    (Category::DiskSpace, "fstatvfs", Signal::Import("_fstatvfs")),
    (
        Category::DiskSpace,
        "getattrlist",
        Signal::Import("_getattrlist"),
    ),
    (
        Category::DiskSpace,
        "fgetattrlist",
        Signal::Import("_fgetattrlist"),
    ),
    (
        Category::DiskSpace,
        "getattrlistat",
        Signal::Import("_getattrlistat"),
    ),
    (
        Category::ActiveKeyboards,
        "activeInputModes",
        Signal::Selector("activeInputModes"),
    ),
    (
        Category::UserDefaults,
        "UserDefaults",
        Signal::Import("_OBJC_CLASS_$_NSUserDefaults"),
    ),
];

/// One required-reason API an executable uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiUse {
    /// Its category.
    pub category: Category,
    /// The API, as Apple names it (`stat`, `systemUptime`).
    pub api: &'static str,
    /// What shows it: `import _stat`, or `selector systemUptime` (weaker: a method of that
    /// name).
    pub evidence: String,
    /// Shown by a method name only.
    pub by_selector: bool,
}

/// The required-reason APIs an image uses, by category then API. `methnames` is the image's
/// `__objc_methname` section, when it has one.
pub fn apis_in(image: &MachO, methnames: Option<&[u8]>) -> Vec<ApiUse> {
    let selectors: Vec<&[u8]> = methnames
        .map(|bytes| bytes.split(|byte| *byte == 0).collect())
        .unwrap_or_default();
    let mut found: Vec<ApiUse> = APIS
        .iter()
        .filter_map(|(category, api, signal)| match signal {
            Signal::Import(symbol) => image.imports(symbol).then(|| ApiUse {
                category: *category,
                api,
                evidence: format!("import {symbol}"),
                by_selector: false,
            }),
            Signal::Selector(name) => selectors.contains(&name.as_bytes()).then(|| ApiUse {
                category: *category,
                api,
                evidence: format!("selector {name}"),
                by_selector: true,
            }),
        })
        .collect();
    found.sort_by(|left, right| (left.category, left.api).cmp(&(right.category, right.api)));
    found.dedup();
    found
}

/// `NSPrivacyCollectedDataType` values, as Apple lists them (note `PhotosorVideos`).
pub const DATA_TYPES: [&str; 35] = [
    "NSPrivacyCollectedDataTypeName",
    "NSPrivacyCollectedDataTypeEmailAddress",
    "NSPrivacyCollectedDataTypePhoneNumber",
    "NSPrivacyCollectedDataTypePhysicalAddress",
    "NSPrivacyCollectedDataTypeOtherUserContactInfo",
    "NSPrivacyCollectedDataTypeHealth",
    "NSPrivacyCollectedDataTypeFitness",
    "NSPrivacyCollectedDataTypePaymentInfo",
    "NSPrivacyCollectedDataTypeCreditInfo",
    "NSPrivacyCollectedDataTypeOtherFinancialInfo",
    "NSPrivacyCollectedDataTypePreciseLocation",
    "NSPrivacyCollectedDataTypeCoarseLocation",
    "NSPrivacyCollectedDataTypeSensitiveInfo",
    "NSPrivacyCollectedDataTypeContacts",
    "NSPrivacyCollectedDataTypeEmailsOrTextMessages",
    "NSPrivacyCollectedDataTypePhotosorVideos",
    "NSPrivacyCollectedDataTypeAudioData",
    "NSPrivacyCollectedDataTypeGameplayContent",
    "NSPrivacyCollectedDataTypeCustomerSupport",
    "NSPrivacyCollectedDataTypeOtherUserContent",
    "NSPrivacyCollectedDataTypeBrowsingHistory",
    "NSPrivacyCollectedDataTypeSearchHistory",
    "NSPrivacyCollectedDataTypeUserID",
    "NSPrivacyCollectedDataTypeDeviceID",
    "NSPrivacyCollectedDataTypePurchaseHistory",
    "NSPrivacyCollectedDataTypeProductInteraction",
    "NSPrivacyCollectedDataTypeAdvertisingData",
    "NSPrivacyCollectedDataTypeOtherUsageData",
    "NSPrivacyCollectedDataTypeCrashData",
    "NSPrivacyCollectedDataTypePerformanceData",
    "NSPrivacyCollectedDataTypeOtherDiagnosticData",
    "NSPrivacyCollectedDataTypeEnvironmentScanning",
    "NSPrivacyCollectedDataTypeHands",
    "NSPrivacyCollectedDataTypeHead",
    "NSPrivacyCollectedDataTypeOtherDataTypes",
];

/// `NSPrivacyCollectedDataTypePurposes` values.
pub const PURPOSES: [&str; 6] = [
    "NSPrivacyCollectedDataTypePurposeThirdPartyAdvertising",
    "NSPrivacyCollectedDataTypePurposeDeveloperAdvertising",
    "NSPrivacyCollectedDataTypePurposeAnalytics",
    "NSPrivacyCollectedDataTypePurposeProductPersonalization",
    "NSPrivacyCollectedDataTypePurposeAppFunctionality",
    "NSPrivacyCollectedDataTypePurposeOther",
];

/// Apple's commonly used third-party SDKs, which must ship their own privacy manifest (and a
/// signature, for binary dependencies). Apple lists "BoringSSL / openssl_grpc" as one entry;
/// both names are kept.
pub const LISTED_SDKS: [&str; 87] = [
    "Abseil",
    "AFNetworking",
    "Alamofire",
    "AppAuth",
    "BoringSSL",
    "openssl_grpc",
    "Capacitor",
    "Charts",
    "connectivity_plus",
    "Cordova",
    "device_info_plus",
    "DKImagePickerController",
    "DKPhotoGallery",
    "FBAEMKit",
    "FBLPromises",
    "FBSDKCoreKit",
    "FBSDKCoreKit_Basics",
    "FBSDKLoginKit",
    "FBSDKShareKit",
    "file_picker",
    "FirebaseABTesting",
    "FirebaseAuth",
    "FirebaseCore",
    "FirebaseCoreDiagnostics",
    "FirebaseCoreExtension",
    "FirebaseCoreInternal",
    "FirebaseCrashlytics",
    "FirebaseDynamicLinks",
    "FirebaseFirestore",
    "FirebaseInstallations",
    "FirebaseMessaging",
    "FirebaseRemoteConfig",
    "Flutter",
    "flutter_inappwebview",
    "flutter_local_notifications",
    "fluttertoast",
    "FMDB",
    "geolocator_apple",
    "GoogleDataTransport",
    "GoogleSignIn",
    "GoogleToolboxForMac",
    "GoogleUtilities",
    "grpcpp",
    "GTMAppAuth",
    "GTMSessionFetcher",
    "hermes",
    "image_picker_ios",
    "IQKeyboardManager",
    "IQKeyboardManagerSwift",
    "Kingfisher",
    "leveldb",
    "Lottie",
    "MBProgressHUD",
    "nanopb",
    "OneSignal",
    "OneSignalCore",
    "OneSignalExtension",
    "OneSignalOutcomes",
    "OpenSSL",
    "OrderedSet",
    "package_info",
    "package_info_plus",
    "path_provider",
    "path_provider_ios",
    "Promises",
    "Protobuf",
    "Reachability",
    "RealmSwift",
    "RxCocoa",
    "RxRelay",
    "RxSwift",
    "SDWebImage",
    "share_plus",
    "shared_preferences_ios",
    "SnapKit",
    "sqflite",
    "Starscream",
    "SVProgressHUD",
    "SwiftyGif",
    "SwiftyJSON",
    "Toast",
    "UnityFramework",
    "url_launcher",
    "url_launcher_ios",
    "video_player_avfoundation",
    "wakelock",
    "webview_flutter_wkwebview",
];

/// The listed SDK a framework is, by its bundle name (`Alamofire` for `Alamofire.framework`).
/// Apple does not say how it recognises an SDK; its emails name the framework's path.
pub fn listed_sdk(framework_name: &str) -> Option<&'static str> {
    LISTED_SDKS
        .iter()
        .copied()
        .find(|sdk| *sdk == framework_name)
}

/// What makes a privacy manifest invalid, beyond its structure (TN3181).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestProblem {
    /// A key with the wrong type or missing (see [`super::PrivacyManifest::structure_problems`]).
    Structure(String),
    /// `NSPrivacyAccessedAPITypes` is an empty array.
    EmptyAccessedApiTypes,
    /// An `NSPrivacyAccessedAPIType` that is not one of the five categories.
    UnknownCategory(String),
    /// An entry's `NSPrivacyAccessedAPITypeReasons` is empty.
    NoReasons(String),
    /// A reason code that is not approved for its category (App Store Connect: ITMS-91055).
    InvalidReason {
        /// The category.
        category: String,
        /// The code.
        reason: String,
    },
    /// An `NSPrivacyCollectedDataType` Apple does not define.
    UnknownDataType(String),
    /// An `NSPrivacyCollectedDataTypePurposes` value Apple does not define.
    UnknownPurpose(String),
    /// `NSPrivacyTracking` is true but no tracking domain is listed.
    TrackingWithoutDomains,
    /// Tracking domains are listed while `NSPrivacyTracking` is false.
    DomainsWithoutTracking,
    /// A tracking domain with a scheme, path, query or trailing slash.
    MalformedDomain(String),
}

impl std::fmt::Display for ManifestProblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Structure(problem) => formatter.write_str(problem),
            Self::EmptyAccessedApiTypes => {
                formatter.write_str("NSPrivacyAccessedAPITypes is empty")
            }
            Self::UnknownCategory(category) => {
                write!(
                    formatter,
                    "{category:?} is not a required-reason API category"
                )
            }
            Self::NoReasons(category) => write!(formatter, "{category} lists no reason"),
            Self::InvalidReason { category, reason } => {
                write!(
                    formatter,
                    "{reason} is not an approved reason for {category}"
                )
            }
            Self::UnknownDataType(data_type) => {
                write!(
                    formatter,
                    "{data_type:?} is not a collected data type Apple defines"
                )
            }
            Self::UnknownPurpose(purpose) => {
                write!(formatter, "{purpose:?} is not a purpose Apple defines")
            }
            Self::TrackingWithoutDomains => formatter.write_str(
                "NSPrivacyTracking is true but NSPrivacyTrackingDomains lists no domain",
            ),
            Self::DomainsWithoutTracking => formatter.write_str(
                "NSPrivacyTrackingDomains lists domains while NSPrivacyTracking is false",
            ),
            Self::MalformedDomain(domain) => write!(
                formatter,
                "tracking domain {domain:?} is not a bare domain (no scheme, path, query or \
                 trailing slash)"
            ),
        }
    }
}

/// Every reason a manifest is invalid (TN3181), its structure first.
pub fn manifest_problems(manifest: &super::PrivacyManifest) -> Vec<ManifestProblem> {
    let mut problems: Vec<ManifestProblem> = manifest
        .structure_problems
        .iter()
        .cloned()
        .map(ManifestProblem::Structure)
        .collect();
    if manifest.problem.is_some() {
        return problems;
    }
    if manifest.declares_accessed_api_types && manifest.accessed_api_types.is_empty() {
        problems.push(ManifestProblem::EmptyAccessedApiTypes);
    }
    for entry in &manifest.accessed_api_types {
        let Some(key) = &entry.category else {
            continue;
        };
        let Some(category) = Category::of_key(key) else {
            problems.push(ManifestProblem::UnknownCategory(key.clone()));
            continue;
        };
        if entry.reasons.is_empty() {
            problems.push(ManifestProblem::NoReasons(key.clone()));
        }
        for reason in &entry.reasons {
            if !category.reasons().contains(&reason.as_str()) {
                problems.push(ManifestProblem::InvalidReason {
                    category: key.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }
    for entry in &manifest.collected_data_types {
        if let Some(data_type) = &entry.data_type
            && !DATA_TYPES.contains(&data_type.as_str())
        {
            problems.push(ManifestProblem::UnknownDataType(data_type.clone()));
        }
        for purpose in &entry.purposes {
            if !PURPOSES.contains(&purpose.as_str()) {
                problems.push(ManifestProblem::UnknownPurpose(purpose.clone()));
            }
        }
    }
    match (manifest.tracking, manifest.tracking_domains.is_empty()) {
        (Some(true), true) => problems.push(ManifestProblem::TrackingWithoutDomains),
        (Some(false) | None, false) => problems.push(ManifestProblem::DomainsWithoutTracking),
        _ => {}
    }
    for domain in &manifest.tracking_domains {
        if domain.contains("://")
            || domain.contains(['/', '?', '#'])
            || domain.trim() != domain
            || domain.is_empty()
        {
            problems.push(ManifestProblem::MalformedDomain(domain.clone()));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_hold_apples_counts() {
        let reasons: usize = Category::ALL
            .iter()
            .map(|category| category.reasons().len())
            .sum();
        assert_eq!(reasons, 17);
        for category in Category::ALL {
            assert_eq!(Category::of_key(category.key()), Some(category));
        }
        // 86 entries on Apple's page, one of them naming two frameworks.
        assert_eq!(LISTED_SDKS.len(), 87);
        assert_eq!(listed_sdk("Alamofire"), Some("Alamofire"));
        assert_eq!(listed_sdk("alamofire"), None);
    }
}
