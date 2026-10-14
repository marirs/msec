//! Google Play store readiness: what in the manifest and the package layout makes Google Play
//! refuse an upload, ask for a Play Console declaration, or what crashes on current Android
//! versions. MobSF has no such checks; every rule here is [`Origin::Msec`].
//!
//! Sources, checked on 2026-10-14:
//! - Target API levels: developer.android.com/google/play/requirements/target-sdk and Play
//!   Console Help 11926878.
//! - `versionCode` range: developer.android.com/studio/publish/versioning ("The greatest value
//!   Google Play allows for versionCode is 2100000000").
//! - `com.example`: Play Console refuses it ("You need to use a different package name
//!   because "com.example" is restricted").
//! - 64-bit native code: developer.android.com/google/play/requirements/64-bit.
//! - Restricted permissions: Play Console Help 9214102 (SMS and Call Log), 10158779
//!   (QUERY_ALL_PACKAGES), 10467955 (All files access), 12085295 (REQUEST_INSTALL_PACKAGES),
//!   9799150 (background location), 14115180 (photo and video), 13392821 (foreground service
//!   and full-screen intent).
//! - Foreground service types: developer.android.com/about/versions/14/changes/fgs-types-required.

use super::{Origin, Severity};
use crate::android::inventory::{Abi, Inventory};
use crate::android::manifest::{ComponentKind, Manifest, foreground_service_types};

/// Android 14: foreground services must declare a type, and each type needs its permission.
const FOREGROUND_SERVICE_TYPES_REQUIRED_FROM: u32 = 34;
/// Google Play's largest `versionCode`.
const MAX_PLAY_VERSION_CODE: u64 = 2_100_000_000;
const FOREGROUND_SERVICE: &str = "android.permission.FOREGROUND_SERVICE";

/// A store-readiness rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreRule {
    /// The target API level is below Google Play's requirement for new apps and updates.
    TargetSdkBelowPlayRequirement,
    /// The package name is in the `com.example` namespace, which Google Play refuses.
    ExamplePackageName,
    /// `versionCode` is missing, zero or above Google Play's maximum.
    VersionCodeOutOfRange,
    /// 32-bit native code without the 64-bit code Google Play requires next to it.
    Missing64BitNativeCode,
    /// A permission Google Play restricts to eligible core uses: Play asks for a declaration
    /// and approves apps whose use qualifies. Not a rejection by itself.
    RestrictedPermission,
    /// A foreground service type whose permission is not requested: Android 14+ refuses to
    /// start the service.
    ForegroundServicePermissionMissing,
    /// Foreground services are used but no service declares a type: Android 14+ refuses to
    /// start an untyped foreground service.
    ForegroundServiceTypeMissing,
}

impl StoreRule {
    /// Engine key.
    pub fn key(self) -> &'static str {
        match self {
            Self::TargetSdkBelowPlayRequirement => "msec_store_target_sdk_below_play",
            Self::ExamplePackageName => "msec_store_example_package",
            Self::VersionCodeOutOfRange => "msec_store_version_code_out_of_range",
            Self::Missing64BitNativeCode => "msec_store_missing_64bit_code",
            Self::RestrictedPermission => "msec_store_restricted_permission",
            Self::ForegroundServicePermissionMissing => "msec_store_fgs_permission_missing",
            Self::ForegroundServiceTypeMissing => "msec_store_fgs_type_missing",
        }
    }

    /// Severity on MobSF's scale: refused uploads and crashes are high, an untyped foreground
    /// service is a warning, and a declaration to file is information.
    pub fn severity(self) -> Severity {
        match self {
            Self::RestrictedPermission => Severity::Info,
            Self::ForegroundServiceTypeMissing => Severity::Warning,
            _ => Severity::High,
        }
    }

    /// Where the rule comes from.
    pub fn origin(self) -> Origin {
        Origin::Msec
    }
}

/// One store-readiness finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFinding {
    /// The rule.
    pub rule: StoreRule,
    /// What it is about: a permission, a service, an ABI. `None` for app-wide settings.
    pub subject: Option<String>,
    /// The permission concerned when the subject is a service (the missing foreground service
    /// permission, or the service's binding permission), so findings about one service stay
    /// distinct.
    pub permission: Option<String>,
    /// What triggered it, in words.
    pub detail: String,
}

/// The device type a Google Play requirement depends on, from required `<uses-feature>`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormFactor {
    /// Phones, tablets and anything without one of the features below.
    PhoneTablet,
    /// Wear OS (`android.hardware.type.watch`).
    Wear,
    /// Android TV (`android.software.leanback`).
    Tv,
    /// Android Automotive OS (`android.hardware.type.automotive`).
    Automotive,
}

impl FormFactor {
    /// From the manifest's required features. Android XR has no requirement of its own here
    /// yet; XR apps get the phone and tablet requirement, the stricter one.
    pub fn of(manifest: &Manifest) -> Self {
        let requires = |feature: &str| {
            manifest
                .features
                .iter()
                .any(|uses| uses.required && uses.name.as_deref() == Some(feature))
        };
        if requires("android.hardware.type.watch") {
            Self::Wear
        } else if requires("android.software.leanback") {
            Self::Tv
        } else if requires("android.hardware.type.automotive") {
            Self::Automotive
        } else {
            Self::PhoneTablet
        }
    }

    /// In words.
    pub fn label(self) -> &'static str {
        match self {
            Self::PhoneTablet => "phones and tablets",
            Self::Wear => "Wear OS",
            Self::Tv => "Android TV",
            Self::Automotive => "Android Automotive OS",
        }
    }
}

/// Google Play's target API requirement from one date on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayTargetRequirement {
    /// First day the requirement applies (`yyyy-MM-dd`).
    pub since: &'static str,
    /// Last day of the extension Play grants on request, if any.
    pub extension_until: Option<&'static str>,
    /// New apps and updates must target at least this, per form factor.
    new_and_updates: [(FormFactor, u32); 4],
    /// Existing apps below this stay installable only on devices at or below their target,
    /// per form factor; `None` where Play states no threshold for the period.
    existing: Option<[(FormFactor, u32); 4]>,
}

impl PlayTargetRequirement {
    /// The minimum target API for new apps and updates.
    pub fn new_and_updates(&self, form: FormFactor) -> u32 {
        lookup(&self.new_and_updates, form)
    }

    /// The minimum target API for existing apps to remain available to new users.
    pub fn existing(&self, form: FormFactor) -> Option<u32> {
        self.existing.as_ref().map(|table| lookup(table, form))
    }
}

fn lookup(table: &[(FormFactor, u32); 4], form: FormFactor) -> u32 {
    table
        .iter()
        .find(|(candidate, _)| *candidate == form)
        .map_or(0, |(_, level)| *level)
}

/// Google Play's requirements, oldest first. Play Console Help 11926878 lists Android TV's
/// API 34 under both 2025 and 2026; the 2025 row follows its table. Add a row when Google
/// announces the next one (Android 17, API 37, expected for August 2027).
pub const PLAY_TARGET_REQUIREMENTS: [PlayTargetRequirement; 2] = [
    PlayTargetRequirement {
        since: "2025-08-31",
        // The 2025 extension date was not re-checked; only the 2026 one is stated here.
        extension_until: None,
        new_and_updates: [
            (FormFactor::PhoneTablet, 35),
            (FormFactor::Wear, 34),
            (FormFactor::Tv, 34),
            (FormFactor::Automotive, 34),
        ],
        existing: None,
    },
    PlayTargetRequirement {
        since: "2026-08-31",
        extension_until: Some("2026-11-01"),
        new_and_updates: [
            (FormFactor::PhoneTablet, 36),
            (FormFactor::Wear, 35),
            (FormFactor::Tv, 34),
            (FormFactor::Automotive, 35),
        ],
        existing: Some([
            (FormFactor::PhoneTablet, 35),
            (FormFactor::Wear, 34),
            (FormFactor::Tv, 33),
            (FormFactor::Automotive, 32),
        ]),
    },
];

/// The requirement in force on `today` (`yyyy-MM-dd`), if the table covers that date.
pub fn play_target_requirement(today: &str) -> Option<&'static PlayTargetRequirement> {
    PLAY_TARGET_REQUIREMENTS
        .iter()
        .rev()
        .find(|requirement| requirement.since <= today)
}

/// Permissions Google Play restricts: `(permission, policy, lowest target API it applies to)`.
pub const PLAY_RESTRICTED_PERMISSIONS: [(&str, &str, u32); 18] = [
    (
        "android.permission.READ_SMS",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.SEND_SMS",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.WRITE_SMS",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.RECEIVE_SMS",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.RECEIVE_MMS",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.RECEIVE_WAP_PUSH",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.READ_CALL_LOG",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.WRITE_CALL_LOG",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.PROCESS_OUTGOING_CALLS",
        "SMS and Call Log permissions",
        1,
    ),
    (
        "android.permission.QUERY_ALL_PACKAGES",
        "Package visibility (QUERY_ALL_PACKAGES)",
        30,
    ),
    (
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "All files access",
        30,
    ),
    (
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "Request install packages",
        1,
    ),
    (
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "Background location",
        29,
    ),
    ("android.permission.USE_EXACT_ALARM", "Exact alarms", 33),
    (
        "android.permission.USE_FULL_SCREEN_INTENT",
        "Full-screen intents",
        34,
    ),
    (
        "android.permission.READ_MEDIA_IMAGES",
        "Photo and video permissions",
        33,
    ),
    (
        "android.permission.READ_MEDIA_VIDEO",
        "Photo and video permissions",
        33,
    ),
    (
        "android.permission.health.",
        "Health Connect permissions",
        1,
    ),
];

/// Services bound by the system under a permission Google Play reviews: the declaration the
/// service implies.
const PLAY_REVIEWED_SERVICE_PERMISSIONS: [(&str, &str); 2] = [
    (
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "Accessibility API",
    ),
    ("android.permission.BIND_VPN_SERVICE", "VpnService"),
];

/// `(32-bit ABI, the 64-bit ABI Google Play requires next to it)`.
const ABI_PAIRS: [(Abi, Abi); 3] = [
    (Abi::ArmeabiV7a, Abi::Arm64V8a),
    (Abi::Armeabi, Abi::Arm64V8a),
    (Abi::X86, Abi::X86_64),
];

/// Runs every store-readiness check. `today` (`yyyy-MM-dd`) picks the target API requirement.
pub fn analyse_store(manifest: &Manifest, inventory: &Inventory, today: &str) -> Vec<StoreFinding> {
    let mut findings = Vec::new();
    let target_sdk = manifest
        .target_sdk()
        .or_else(|| manifest.min_sdk())
        .unwrap_or(1);
    check_target_sdk(manifest, target_sdk, today, &mut findings);
    check_package_name(manifest, &mut findings);
    check_version_code(manifest, &mut findings);
    check_64_bit_code(inventory, &mut findings);
    check_restricted_permissions(manifest, target_sdk, &mut findings);
    check_foreground_services(manifest, target_sdk, &mut findings);
    findings
}

fn check_target_sdk(
    manifest: &Manifest,
    target_sdk: u32,
    today: &str,
    findings: &mut Vec<StoreFinding>,
) {
    let Some(requirement) = play_target_requirement(today) else {
        return;
    };
    let form = FormFactor::of(manifest);
    let required = requirement.new_and_updates(form);
    if target_sdk >= required {
        return;
    }
    let mut detail = format!(
        "targets API {target_sdk}; since {}, Google Play requires API {required} for new apps \
         and updates on {}",
        requirement.since,
        form.label()
    );
    if let Some(until) = requirement.extension_until.filter(|until| *until >= today) {
        detail.push_str(&format!(" (an extension to {until} can be requested)"));
    }
    if let Some(existing) = requirement
        .existing(form)
        .filter(|level| target_sdk < *level)
    {
        detail.push_str(&format!(
            "; below API {existing}, the published app is also hidden from new users on newer \
             Android versions"
        ));
    }
    findings.push(StoreFinding {
        rule: StoreRule::TargetSdkBelowPlayRequirement,
        permission: None,
        subject: None,
        detail,
    });
}

fn check_package_name(manifest: &Manifest, findings: &mut Vec<StoreFinding>) {
    let Some(package) = manifest.package.as_deref() else {
        return;
    };
    if package == "com.example" || package.starts_with("com.example.") {
        findings.push(StoreFinding {
            rule: StoreRule::ExamplePackageName,
            permission: None,
            subject: None,
            detail: format!("package {package} is in the com.example namespace"),
        });
    }
}

fn check_version_code(manifest: &Manifest, findings: &mut Vec<StoreFinding>) {
    let detail = match manifest.version_code {
        None => "no android:versionCode".to_owned(),
        Some(0) => "android:versionCode is 0".to_owned(),
        Some(code) if code > MAX_PLAY_VERSION_CODE => {
            format!("android:versionCode {code} is above {MAX_PLAY_VERSION_CODE}")
        }
        Some(_) => return,
    };
    findings.push(StoreFinding {
        rule: StoreRule::VersionCodeOutOfRange,
        permission: None,
        subject: None,
        detail,
    });
}

/// Each 32-bit ABI with libraries needs its 64-bit ABI; where both exist, every 32-bit library
/// needs a 64-bit build, or loading it fails on 64-bit-only devices.
fn check_64_bit_code(inventory: &Inventory, findings: &mut Vec<StoreFinding>) {
    let libraries_of = |abi: &Abi| -> Option<&Vec<String>> {
        inventory
            .abis
            .iter()
            .find(|entry| &entry.abi == abi && !entry.libraries.is_empty())
            .map(|entry| &entry.libraries)
    };
    for (bits32, bits64) in &ABI_PAIRS {
        let Some(libraries32) = libraries_of(bits32) else {
            continue;
        };
        let Some(libraries64) = libraries_of(bits64) else {
            findings.push(StoreFinding {
                rule: StoreRule::Missing64BitNativeCode,
                permission: None,
                subject: Some(bits64.name().to_owned()),
                detail: format!(
                    "{} libraries in lib/{} and none in lib/{}",
                    libraries32.len(),
                    bits32.name(),
                    bits64.name()
                ),
            });
            continue;
        };
        let file_name = |path: &String| path.rsplit('/').next().unwrap_or(path).to_owned();
        let names64: Vec<String> = libraries64.iter().map(file_name).collect();
        let missing: Vec<String> = libraries32
            .iter()
            .map(file_name)
            .filter(|name| !names64.contains(name))
            .collect();
        if !missing.is_empty() {
            findings.push(StoreFinding {
                rule: StoreRule::Missing64BitNativeCode,
                permission: None,
                subject: Some(bits64.name().to_owned()),
                detail: format!(
                    "lib/{} has no build of {}",
                    bits64.name(),
                    missing.join(", ")
                ),
            });
        }
    }
}

fn check_restricted_permissions(
    manifest: &Manifest,
    target_sdk: u32,
    findings: &mut Vec<StoreFinding>,
) {
    for permission in &manifest.uses_permissions {
        let restriction = PLAY_RESTRICTED_PERMISSIONS
            .iter()
            .find(|(name, _, _)| {
                if name.ends_with('.') {
                    permission.name.starts_with(name)
                } else {
                    permission.name == *name
                }
            })
            .filter(|(_, _, from_target)| target_sdk >= *from_target);
        if let Some((_, policy, _)) = restriction {
            findings.push(StoreFinding {
                rule: StoreRule::RestrictedPermission,
                permission: None,
                subject: Some(permission.name.clone()),
                detail: format!(
                    "{policy}: declare it in Play Console; Play approves eligible core uses"
                ),
            });
        }
    }
    let services = manifest
        .application
        .iter()
        .flat_map(|application| application.components_of(ComponentKind::Service));
    for service in services {
        let reviewed = PLAY_REVIEWED_SERVICE_PERMISSIONS
            .iter()
            .find(|(permission, _)| service.permission.as_deref() == Some(*permission));
        if let Some((permission, policy)) = reviewed {
            findings.push(StoreFinding {
                rule: StoreRule::RestrictedPermission,
                permission: Some((*permission).to_owned()),
                subject: Some(service.name.clone()),
                detail: format!(
                    "{policy}: a service bound with {permission} needs a Play Console declaration"
                ),
            });
        }
    }
}

fn check_foreground_services(
    manifest: &Manifest,
    target_sdk: u32,
    findings: &mut Vec<StoreFinding>,
) {
    if target_sdk < FOREGROUND_SERVICE_TYPES_REQUIRED_FROM {
        return;
    }
    let requested = |name: &str| {
        manifest
            .uses_permissions
            .iter()
            .any(|permission| permission.name == name)
    };
    let services: Vec<_> = manifest
        .application
        .iter()
        .flat_map(|application| application.components_of(ComponentKind::Service))
        .collect();
    let mut typed_services = 0;
    for service in &services {
        let Some(flags) = service.foreground_service_type.filter(|flags| *flags != 0) else {
            continue;
        };
        typed_services += 1;
        // `(what needs it, permission)`: every foreground service needs FOREGROUND_SERVICE,
        // and each declared type its own permission.
        let needed = std::iter::once(("a foreground service".to_owned(), Some(FOREGROUND_SERVICE)))
            .chain(
                foreground_service_types(flags)
                    .into_iter()
                    .map(|(name, permission)| (format!("type {name}"), permission)),
            );
        for (what, permission) in needed {
            let Some(permission) = permission.filter(|permission| !requested(permission)) else {
                continue;
            };
            findings.push(StoreFinding {
                rule: StoreRule::ForegroundServicePermissionMissing,
                permission: Some(permission.to_owned()),
                subject: Some(service.name.clone()),
                detail: format!("{what} needs {permission}, which is not requested"),
            });
        }
    }
    if typed_services == 0 && requested(FOREGROUND_SERVICE) {
        findings.push(StoreFinding {
            rule: StoreRule::ForegroundServiceTypeMissing,
            permission: None,
            subject: None,
            detail: format!(
                "requests {FOREGROUND_SERVICE}, but none of its {} services declares \
                 android:foregroundServiceType",
                services.len()
            ),
        });
    }
}
