//! The app manifest as Android's package parser reads it: `android:` attributes by resource ID,
//! Android's defaults applied, class names expanded the way the platform expands them.
//!
//! Values that may be resource references (label, icon, version name) are kept as [`Value`]s;
//! [`super::Apk`] resolves them against the resource table.

use super::value::Value;
use super::xml::{XmlDocument, XmlElement};

/// Framework attribute resource IDs (`android.R.attr`). Checked against the generated table
/// from the Android SDK in this module's tests.
pub(crate) mod attr {
    pub(crate) const LABEL: u32 = 0x0101_0001;
    pub(crate) const ICON: u32 = 0x0101_0002;
    pub(crate) const NAME: u32 = 0x0101_0003;
    pub(crate) const PERMISSION: u32 = 0x0101_0006;
    pub(crate) const READ_PERMISSION: u32 = 0x0101_0007;
    pub(crate) const WRITE_PERMISSION: u32 = 0x0101_0008;
    pub(crate) const PROTECTION_LEVEL: u32 = 0x0101_0009;
    pub(crate) const PERMISSION_GROUP: u32 = 0x0101_000a;
    pub(crate) const SHARED_USER_ID: u32 = 0x0101_000b;
    pub(crate) const ENABLED: u32 = 0x0101_000e;
    pub(crate) const DEBUGGABLE: u32 = 0x0101_000f;
    pub(crate) const EXPORTED: u32 = 0x0101_0010;
    pub(crate) const PROCESS: u32 = 0x0101_0011;
    pub(crate) const AUTHORITIES: u32 = 0x0101_0018;
    pub(crate) const GRANT_URI_PERMISSIONS: u32 = 0x0101_001b;
    pub(crate) const PRIORITY: u32 = 0x0101_001c;
    pub(crate) const VALUE: u32 = 0x0101_0024;
    pub(crate) const RESOURCE: u32 = 0x0101_0025;
    pub(crate) const MIME_TYPE: u32 = 0x0101_0026;
    pub(crate) const SCHEME: u32 = 0x0101_0027;
    pub(crate) const HOST: u32 = 0x0101_0028;
    pub(crate) const PORT: u32 = 0x0101_0029;
    pub(crate) const PATH: u32 = 0x0101_002a;
    pub(crate) const PATH_PREFIX: u32 = 0x0101_002b;
    pub(crate) const PATH_PATTERN: u32 = 0x0101_002c;
    pub(crate) const TARGET_ACTIVITY: u32 = 0x0101_0202;
    pub(crate) const MIN_SDK_VERSION: u32 = 0x0101_020c;
    pub(crate) const VERSION_CODE: u32 = 0x0101_021b;
    pub(crate) const VERSION_NAME: u32 = 0x0101_021c;
    pub(crate) const ANY_DENSITY: u32 = 0x0101_026c;
    pub(crate) const TARGET_SDK_VERSION: u32 = 0x0101_0270;
    pub(crate) const MAX_SDK_VERSION: u32 = 0x0101_0271;
    pub(crate) const TEST_ONLY: u32 = 0x0101_0272;
    pub(crate) const BACKUP_AGENT: u32 = 0x0101_027f;
    pub(crate) const ALLOW_BACKUP: u32 = 0x0101_0280;
    pub(crate) const GL_ES_VERSION: u32 = 0x0101_0281;
    pub(crate) const SMALL_SCREENS: u32 = 0x0101_0284;
    pub(crate) const NORMAL_SCREENS: u32 = 0x0101_0285;
    pub(crate) const LARGE_SCREENS: u32 = 0x0101_0286;
    pub(crate) const RESIZEABLE: u32 = 0x0101_028d;
    pub(crate) const REQUIRED: u32 = 0x0101_028e;
    pub(crate) const INSTALL_LOCATION: u32 = 0x0101_02b7;
    pub(crate) const XLARGE_SCREENS: u32 = 0x0101_02bf;
    pub(crate) const LARGE_HEAP: u32 = 0x0101_035a;
    pub(crate) const REQUIRES_SMALLEST_WIDTH_DP: u32 = 0x0101_0364;
    pub(crate) const EXTRACT_NATIVE_LIBS: u32 = 0x0101_04ea;
    pub(crate) const FULL_BACKUP_CONTENT: u32 = 0x0101_04eb;
    pub(crate) const USES_CLEARTEXT_TRAFFIC: u32 = 0x0101_04ec;
    pub(crate) const AUTO_VERIFY: u32 = 0x0101_04ee;
    pub(crate) const NETWORK_SECURITY_CONFIG: u32 = 0x0101_0527;
    pub(crate) const ROUND_ICON: u32 = 0x0101_052c;
    pub(crate) const COMPILE_SDK_VERSION: u32 = 0x0101_0572;
    pub(crate) const COMPILE_SDK_VERSION_CODENAME: u32 = 0x0101_0573;
    pub(crate) const VERSION_CODE_MAJOR: u32 = 0x0101_0576;
    pub(crate) const APP_COMPONENT_FACTORY: u32 = 0x0101_057a;
    pub(crate) const HAS_FRAGILE_USER_DATA: u32 = 0x0101_059a;
    pub(crate) const REQUEST_LEGACY_EXTERNAL_STORAGE: u32 = 0x0101_0603;
    pub(crate) const PATH_SUFFIX: u32 = 0x0101_061e;
    pub(crate) const PATH_ADVANCED_PATTERN: u32 = 0x0101_0620;
    pub(crate) const DATA_EXTRACTION_RULES: u32 = 0x0101_063e;
    pub(crate) const USES_PERMISSION_FLAGS: u32 = 0x0101_0644;
}

/// `usesPermissionFlags="neverForLocation"`.
const NEVER_FOR_LOCATION: i64 = 0x0001_0000;
/// Android 12: components with intent filters must declare `android:exported`.
const EXPLICIT_EXPORT_REQUIRED_FROM: u32 = 31;
/// Android 4.2: content providers stopped being exported by default.
const PROVIDERS_PRIVATE_FROM: u32 = 17;

/// An SDK level: an API number, or a preview codename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkLevel {
    /// API level.
    Api(u32),
    /// Preview codename (the app was built against a preview SDK).
    Codename(String),
}

impl SdkLevel {
    /// The API level, when numeric.
    pub fn api(&self) -> Option<u32> {
        match self {
            Self::Api(level) => Some(*level),
            Self::Codename(_) => None,
        }
    }

    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::String(Some(text)) => match text.trim().parse() {
                Ok(level) => Some(Self::Api(level)),
                Err(_) => Some(Self::Codename(text.trim().to_owned())),
            },
            other => other
                .as_integer()
                .and_then(|level| u32::try_from(level).ok())
                .map(Self::Api),
        }
    }
}

/// Where the app may be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallLocation {
    /// Let the system decide.
    Auto,
    /// Internal storage only.
    InternalOnly,
    /// External storage preferred.
    PreferExternal,
}

/// A `<uses-permission>` (or `<uses-permission-sdk-23>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsesPermission {
    /// Permission name.
    pub name: String,
    /// Requested only up to this API level.
    pub max_sdk: Option<u32>,
    /// From `<uses-permission-sdk-23>`: requested only on Android 6.0 and later.
    pub sdk_23_and_later: bool,
    /// `usesPermissionFlags="neverForLocation"`.
    pub never_for_location: bool,
}

/// A `<permission>` the app defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredPermission {
    /// Permission name.
    pub name: String,
    /// Raw `protectionLevel` flags: base level in the low 4 bits (0 normal, 1 dangerous,
    /// 2 signature, 3 signatureOrSystem). Android's default is normal.
    pub protection_level: i64,
    /// Permission group.
    pub group: Option<String>,
}

/// A `<uses-feature>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsesFeature {
    /// Feature name; `None` for an OpenGL ES requirement.
    pub name: Option<String>,
    /// Devices without the feature cannot install the app (Google Play filters them out).
    pub required: bool,
    /// Required OpenGL ES version (`0x00030000` is 3.0).
    pub gl_es_version: Option<u32>,
}

/// `<supports-screens>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SupportsScreens {
    /// Small screens.
    pub small: Option<bool>,
    /// Normal screens.
    pub normal: Option<bool>,
    /// Large screens.
    pub large: Option<bool>,
    /// Extra-large screens.
    pub xlarge: Option<bool>,
    /// Any density.
    pub any_density: Option<bool>,
    /// Resizeable (obsolete).
    pub resizeable: Option<bool>,
    /// Smallest screen width required, in dp.
    pub requires_smallest_width_dp: Option<u32>,
}

/// `<queries>`: other apps this app can see on Android 11 and later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Queries {
    /// Package names.
    pub packages: Vec<String>,
    /// Number of `<intent>` queries.
    pub intents: usize,
    /// Provider authorities.
    pub providers: Vec<String>,
}

/// A `<meta-data>`.
#[derive(Debug, Clone, PartialEq)]
pub struct MetaData {
    /// Name.
    pub name: String,
    /// `android:value`.
    pub value: Option<Value>,
    /// `android:resource`.
    pub resource: Option<Value>,
}

/// A `<uses-library>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsesLibrary {
    /// Library name.
    pub name: String,
    /// The app does not install without it.
    pub required: bool,
}

/// What kind of component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentKind {
    /// `<activity>`.
    Activity,
    /// `<activity-alias>`.
    ActivityAlias,
    /// `<service>`.
    Service,
    /// `<receiver>`.
    Receiver,
    /// `<provider>`.
    Provider,
}

impl ComponentKind {
    fn element_name(self) -> &'static str {
        match self {
            Self::Activity => "activity",
            Self::ActivityAlias => "activity-alias",
            Self::Service => "service",
            Self::Receiver => "receiver",
            Self::Provider => "provider",
        }
    }

    const ALL: [Self; 5] = [
        Self::Activity,
        Self::ActivityAlias,
        Self::Service,
        Self::Receiver,
        Self::Provider,
    ];
}

/// One `<data>` element of an intent filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntentData {
    /// URI scheme.
    pub scheme: Option<String>,
    /// Host.
    pub host: Option<String>,
    /// Port.
    pub port: Option<String>,
    /// Exact path.
    pub path: Option<String>,
    /// Path prefix.
    pub path_prefix: Option<String>,
    /// Path pattern (simple glob).
    pub path_pattern: Option<String>,
    /// Path suffix.
    pub path_suffix: Option<String>,
    /// Advanced path pattern.
    pub path_advanced_pattern: Option<String>,
    /// MIME type.
    pub mime_type: Option<String>,
}

/// An `<intent-filter>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntentFilter {
    /// Actions.
    pub actions: Vec<String>,
    /// Categories.
    pub categories: Vec<String>,
    /// Data elements. Android combines them: every scheme with every host with every path.
    pub data: Vec<IntentData>,
    /// `android:autoVerify` (App Links).
    pub auto_verify: Option<bool>,
    /// Priority.
    pub priority: Option<i64>,
}

impl IntentFilter {
    /// `MAIN` + `LAUNCHER`: the activity on the home screen.
    pub fn is_launcher(&self) -> bool {
        self.has_action("android.intent.action.MAIN")
            && self.has_category("android.intent.category.LAUNCHER")
    }

    /// `VIEW` + `BROWSABLE`: reachable from links in a browser or another app.
    pub fn is_browsable(&self) -> bool {
        self.has_action("android.intent.action.VIEW")
            && self.has_category("android.intent.category.BROWSABLE")
    }

    /// Has this action.
    pub fn has_action(&self, action: &str) -> bool {
        self.actions.iter().any(|candidate| candidate == action)
    }

    /// Has this category.
    pub fn has_category(&self, category: &str) -> bool {
        self.categories
            .iter()
            .any(|candidate| candidate == category)
    }

    /// Distinct schemes across the data elements.
    pub fn schemes(&self) -> Vec<&str> {
        distinct(self.data.iter().filter_map(|data| data.scheme.as_deref()))
    }

    /// Distinct hosts across the data elements.
    pub fn hosts(&self) -> Vec<&str> {
        distinct(self.data.iter().filter_map(|data| data.host.as_deref()))
    }
}

fn distinct<'item>(items: impl Iterator<Item = &'item str>) -> Vec<&'item str> {
    let mut seen: Vec<&str> = Vec::new();
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

/// An activity, alias, service, receiver or provider.
#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    /// What kind.
    pub kind: ComponentKind,
    /// Fully qualified class name.
    pub name: String,
    /// `android:exported` as written; see [`Component::is_exported`] for Android's default.
    pub exported: Option<bool>,
    /// `android:enabled`.
    pub enabled: Option<bool>,
    /// Permission callers need.
    pub permission: Option<String>,
    /// Provider read permission.
    pub read_permission: Option<String>,
    /// Provider write permission.
    pub write_permission: Option<String>,
    /// Provider authorities.
    pub authorities: Vec<String>,
    /// Provider `grantUriPermissions`.
    pub grant_uri_permissions: Option<bool>,
    /// Process name.
    pub process: Option<String>,
    /// Alias target.
    pub target_activity: Option<String>,
    /// Intent filters.
    pub intent_filters: Vec<IntentFilter>,
    /// Meta-data.
    pub meta_data: Vec<MetaData>,
}

impl Component {
    /// Whether other apps can start or bind to the component: the explicit attribute, else
    /// Android's default (exported when it has intent filters; providers exported by default
    /// only for apps targeting API 16 and lower).
    pub fn is_exported(&self, target_sdk: u32) -> bool {
        self.exported.unwrap_or(match self.kind {
            ComponentKind::Provider => target_sdk < PROVIDERS_PRIVATE_FROM,
            _ => !self.intent_filters.is_empty(),
        })
    }

    /// An activity or alias on the home screen.
    pub fn is_launcher(&self) -> bool {
        matches!(
            self.kind,
            ComponentKind::Activity | ComponentKind::ActivityAlias
        ) && self.intent_filters.iter().any(IntentFilter::is_launcher)
    }
}

/// `<application>`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Application {
    /// Application class.
    pub name: Option<String>,
    /// Label (often a string reference).
    pub label: Option<Value>,
    /// Icon reference.
    pub icon: Option<Value>,
    /// Round icon reference.
    pub round_icon: Option<Value>,
    /// `android:debuggable`.
    pub debuggable: Option<bool>,
    /// `android:allowBackup` (Android's default is true).
    pub allow_backup: Option<bool>,
    /// `android:testOnly`.
    pub test_only: Option<bool>,
    /// `android:usesCleartextTraffic`.
    pub uses_cleartext_traffic: Option<bool>,
    /// `android:networkSecurityConfig` (an `@xml` reference).
    pub network_security_config: Option<Value>,
    /// `android:extractNativeLibs`.
    pub extract_native_libs: Option<bool>,
    /// `android:requestLegacyExternalStorage`.
    pub request_legacy_external_storage: Option<bool>,
    /// `android:fullBackupContent` (reference or boolean).
    pub full_backup_content: Option<Value>,
    /// `android:dataExtractionRules` (Android 12 and later).
    pub data_extraction_rules: Option<Value>,
    /// `android:hasFragileUserData`.
    pub has_fragile_user_data: Option<bool>,
    /// `android:largeHeap`.
    pub large_heap: Option<bool>,
    /// `android:backupAgent`.
    pub backup_agent: Option<String>,
    /// `android:appComponentFactory`.
    pub app_component_factory: Option<String>,
    /// Components, in manifest order.
    pub components: Vec<Component>,
    /// Application-level meta-data.
    pub meta_data: Vec<MetaData>,
    /// Shared libraries.
    pub uses_libraries: Vec<UsesLibrary>,
}

impl Application {
    /// Components of one kind.
    pub fn components_of(&self, kind: ComponentKind) -> impl Iterator<Item = &Component> {
        self.components
            .iter()
            .filter(move |component| component.kind == kind)
    }
}

/// Something in the manifest that Android rejects or that analysis tools commonly misread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestProblem {
    /// The root element is not `<manifest>`. Android rejects the package.
    RootIsNotManifest {
        /// The root element found.
        found: String,
    },
    /// No `package` attribute. Android rejects the package.
    MissingPackage,
    /// An element that should appear once appears more than once.
    Repeated {
        /// The element name.
        element: &'static str,
    },
    /// A component with intent filters and no `android:exported` in an app targeting Android
    /// 12 or later. Android refuses to install it.
    MissingExported {
        /// The component class.
        component: String,
    },
}

/// The decoded app manifest.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    /// Package name (application ID).
    pub package: Option<String>,
    /// Version code, including `versionCodeMajor` in the upper 32 bits.
    pub version_code: Option<u64>,
    /// Version name (may be a string reference).
    pub version_name: Option<Value>,
    /// SDK the app was compiled against.
    pub compile_sdk: Option<SdkLevel>,
    /// Platform build the manifest was compiled with (`platformBuildVersionName`).
    pub platform_build_version: Option<String>,
    /// `minSdkVersion` as written; see [`Manifest::min_sdk`].
    pub min_sdk_version: Option<SdkLevel>,
    /// `targetSdkVersion` as written; see [`Manifest::target_sdk`].
    pub target_sdk_version: Option<SdkLevel>,
    /// `maxSdkVersion`.
    pub max_sdk: Option<u32>,
    /// `installLocation`.
    pub install_location: Option<InstallLocation>,
    /// `sharedUserId` (deprecated).
    pub shared_user_id: Option<String>,
    /// Requested permissions.
    pub uses_permissions: Vec<UsesPermission>,
    /// Permissions the app defines.
    pub permissions: Vec<DeclaredPermission>,
    /// Hardware and software features.
    pub features: Vec<UsesFeature>,
    /// Screen support.
    pub supports_screens: Option<SupportsScreens>,
    /// Package visibility queries.
    pub queries: Queries,
    /// The application element.
    pub application: Option<Application>,
    /// What Android would reject, or tools commonly misread.
    pub problems: Vec<ManifestProblem>,
}

impl Manifest {
    /// Reads the manifest from a decoded document.
    pub fn from_document(document: &XmlDocument) -> Self {
        let mut manifest = Self::default();
        let Some(root) = &document.root else {
            return manifest;
        };
        if root.name != "manifest" {
            manifest.problems.push(ManifestProblem::RootIsNotManifest {
                found: root.name.clone(),
            });
        }
        manifest.read_root_attributes(root);
        manifest.read_children(root);
        if let Some(application) = &mut manifest.application {
            let package = manifest.package.clone().unwrap_or_default();
            for component in &mut application.components {
                component.name = class_name(&package, &component.name);
                if let Some(target) = &component.target_activity {
                    component.target_activity = Some(class_name(&package, target));
                }
            }
            if let Some(name) = &application.name {
                application.name = Some(class_name(&package, name));
            }
        }
        manifest.check_explicit_exports();
        manifest
    }

    /// Effective minimum SDK: Android's default is 1. `None` for a preview codename.
    pub fn min_sdk(&self) -> Option<u32> {
        match &self.min_sdk_version {
            None => Some(1),
            Some(level) => level.api(),
        }
    }

    /// Effective target SDK: Android's default is the minimum SDK.
    pub fn target_sdk(&self) -> Option<u32> {
        match &self.target_sdk_version {
            None => self.min_sdk(),
            Some(level) => level.api(),
        }
    }

    fn read_root_attributes(&mut self, root: &XmlElement) {
        self.package = root
            .plain_attribute("package")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if self.package.is_none() {
            self.problems.push(ManifestProblem::MissingPackage);
        }
        let minor = integer(root, attr::VERSION_CODE).map(|code| code as u64 & 0xffff_ffff);
        let major =
            integer(root, attr::VERSION_CODE_MAJOR).map(|code| (code as u64 & 0xffff_ffff) << 32);
        self.version_code = match (major, minor) {
            (None, None) => None,
            (major, minor) => Some(major.unwrap_or(0) | minor.unwrap_or(0)),
        };
        self.version_name = root.attribute(attr::VERSION_NAME).cloned();
        self.compile_sdk = root
            .attribute(attr::COMPILE_SDK_VERSION)
            .or_else(|| root.plain_attribute("platformBuildVersionCode"))
            .and_then(SdkLevel::from_value);
        if let Some(Value::String(Some(codename))) =
            root.attribute(attr::COMPILE_SDK_VERSION_CODENAME)
            && self.compile_sdk.is_none()
        {
            self.compile_sdk = Some(SdkLevel::Codename(codename.clone()));
        }
        self.platform_build_version = root
            .plain_attribute("platformBuildVersionName")
            .map(|value| value.to_string())
            .filter(|text| !text.is_empty());
        self.install_location =
            integer(root, attr::INSTALL_LOCATION).and_then(|location| match location {
                0 => Some(InstallLocation::Auto),
                1 => Some(InstallLocation::InternalOnly),
                2 => Some(InstallLocation::PreferExternal),
                _ => None,
            });
        self.shared_user_id = text(root, attr::SHARED_USER_ID);
    }

    fn read_children(&mut self, root: &XmlElement) {
        let mut seen_application = false;
        let mut seen_uses_sdk = false;
        for child in root.elements() {
            match child.name.as_str() {
                // Android reads every <uses-sdk>; the last one's values stand.
                "uses-sdk" => {
                    if std::mem::replace(&mut seen_uses_sdk, true) {
                        self.problems.push(ManifestProblem::Repeated {
                            element: "uses-sdk",
                        });
                    }
                    self.read_uses_sdk(child);
                }
                "uses-permission" | "uses-permission-sdk-m" | "uses-permission-sdk-23" => {
                    if let Some(permission) = read_uses_permission(child) {
                        self.uses_permissions.push(permission);
                    }
                }
                "permission" => self.permissions.extend(read_declared_permission(child)),
                "uses-feature" => self.features.push(read_uses_feature(child)),
                "supports-screens" => self.supports_screens = Some(read_supports_screens(child)),
                "queries" => read_queries(child, &mut self.queries),
                // Android uses the first <application> and rejects packages with more than one.
                "application" => {
                    if std::mem::replace(&mut seen_application, true) {
                        self.problems.push(ManifestProblem::Repeated {
                            element: "application",
                        });
                    } else {
                        self.application = Some(read_application(child));
                    }
                }
                _ => {}
            }
        }
    }

    fn read_uses_sdk(&mut self, element: &XmlElement) {
        if let Some(level) = element
            .attribute(attr::MIN_SDK_VERSION)
            .and_then(SdkLevel::from_value)
        {
            self.min_sdk_version = Some(level);
        }
        if let Some(level) = element
            .attribute(attr::TARGET_SDK_VERSION)
            .and_then(SdkLevel::from_value)
        {
            self.target_sdk_version = Some(level);
        }
        if let Some(level) =
            integer(element, attr::MAX_SDK_VERSION).and_then(|level| u32::try_from(level).ok())
        {
            self.max_sdk = Some(level);
        }
    }

    fn check_explicit_exports(&mut self) {
        let Some(target_sdk) = self.target_sdk() else {
            return;
        };
        let Some(application) = &self.application else {
            return;
        };
        if target_sdk < EXPLICIT_EXPORT_REQUIRED_FROM {
            return;
        }
        let missing = application
            .components
            .iter()
            .filter(|component| component.kind != ComponentKind::Provider)
            .filter(|component| {
                component.exported.is_none() && !component.intent_filters.is_empty()
            })
            .map(|component| ManifestProblem::MissingExported {
                component: component.name.clone(),
            });
        self.problems.extend(missing.collect::<Vec<_>>());
    }
}

fn text(element: &XmlElement, id: u32) -> Option<String> {
    element
        .attribute(id)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn boolean(element: &XmlElement, id: u32) -> Option<bool> {
    element.attribute(id).and_then(Value::as_bool)
}

fn integer(element: &XmlElement, id: u32) -> Option<i64> {
    element.attribute(id).and_then(Value::as_integer)
}

/// `PackageParser.buildClassName`: `.Foo` and `Foo` are relative to the package.
fn class_name(package: &str, name: &str) -> String {
    if name.starts_with('.') {
        format!("{package}{name}")
    } else if !name.contains('.') && !package.is_empty() {
        format!("{package}.{name}")
    } else {
        name.to_owned()
    }
}

fn read_uses_permission(element: &XmlElement) -> Option<UsesPermission> {
    Some(UsesPermission {
        name: text(element, attr::NAME)?,
        max_sdk: integer(element, attr::MAX_SDK_VERSION)
            .and_then(|level| u32::try_from(level).ok()),
        sdk_23_and_later: element.name != "uses-permission",
        never_for_location: integer(element, attr::USES_PERMISSION_FLAGS)
            .is_some_and(|flags| flags & NEVER_FOR_LOCATION != 0),
    })
}

fn read_declared_permission(element: &XmlElement) -> Option<DeclaredPermission> {
    Some(DeclaredPermission {
        name: text(element, attr::NAME)?,
        protection_level: integer(element, attr::PROTECTION_LEVEL).unwrap_or(0),
        group: text(element, attr::PERMISSION_GROUP),
    })
}

fn read_uses_feature(element: &XmlElement) -> UsesFeature {
    UsesFeature {
        name: text(element, attr::NAME),
        required: boolean(element, attr::REQUIRED).unwrap_or(true),
        gl_es_version: integer(element, attr::GL_ES_VERSION)
            .and_then(|version| u32::try_from(version).ok()),
    }
}

fn read_supports_screens(element: &XmlElement) -> SupportsScreens {
    SupportsScreens {
        small: boolean(element, attr::SMALL_SCREENS),
        normal: boolean(element, attr::NORMAL_SCREENS),
        large: boolean(element, attr::LARGE_SCREENS),
        xlarge: boolean(element, attr::XLARGE_SCREENS),
        any_density: boolean(element, attr::ANY_DENSITY),
        resizeable: boolean(element, attr::RESIZEABLE),
        requires_smallest_width_dp: integer(element, attr::REQUIRES_SMALLEST_WIDTH_DP)
            .and_then(|width| u32::try_from(width).ok()),
    }
}

fn read_queries(element: &XmlElement, queries: &mut Queries) {
    for child in element.elements() {
        match child.name.as_str() {
            "package" => queries.packages.extend(text(child, attr::NAME)),
            "intent" => queries.intents += 1,
            "provider" => queries.providers.extend(authorities(child)),
            _ => {}
        }
    }
}

fn authorities(element: &XmlElement) -> Vec<String> {
    text(element, attr::AUTHORITIES)
        .map(|value| {
            value
                .split(';')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn read_application(element: &XmlElement) -> Application {
    let mut application = Application {
        name: text(element, attr::NAME),
        label: element.attribute(attr::LABEL).cloned(),
        icon: element.attribute(attr::ICON).cloned(),
        round_icon: element.attribute(attr::ROUND_ICON).cloned(),
        debuggable: boolean(element, attr::DEBUGGABLE),
        allow_backup: boolean(element, attr::ALLOW_BACKUP),
        test_only: boolean(element, attr::TEST_ONLY),
        uses_cleartext_traffic: boolean(element, attr::USES_CLEARTEXT_TRAFFIC),
        network_security_config: element.attribute(attr::NETWORK_SECURITY_CONFIG).cloned(),
        extract_native_libs: boolean(element, attr::EXTRACT_NATIVE_LIBS),
        request_legacy_external_storage: boolean(element, attr::REQUEST_LEGACY_EXTERNAL_STORAGE),
        full_backup_content: element.attribute(attr::FULL_BACKUP_CONTENT).cloned(),
        data_extraction_rules: element.attribute(attr::DATA_EXTRACTION_RULES).cloned(),
        has_fragile_user_data: boolean(element, attr::HAS_FRAGILE_USER_DATA),
        large_heap: boolean(element, attr::LARGE_HEAP),
        backup_agent: text(element, attr::BACKUP_AGENT),
        app_component_factory: text(element, attr::APP_COMPONENT_FACTORY),
        ..Application::default()
    };
    for child in element.elements() {
        if let Some(kind) = ComponentKind::ALL
            .into_iter()
            .find(|kind| kind.element_name() == child.name)
        {
            application.components.extend(read_component(child, kind));
            continue;
        }
        match child.name.as_str() {
            "meta-data" => application.meta_data.extend(read_meta_data(child)),
            "uses-library" => application
                .uses_libraries
                .extend(text(child, attr::NAME).map(|name| UsesLibrary {
                    name,
                    required: boolean(child, attr::REQUIRED).unwrap_or(true),
                })),
            _ => {}
        }
    }
    application
}

fn read_component(element: &XmlElement, kind: ComponentKind) -> Option<Component> {
    Some(Component {
        kind,
        name: text(element, attr::NAME)?,
        exported: boolean(element, attr::EXPORTED),
        enabled: boolean(element, attr::ENABLED),
        permission: text(element, attr::PERMISSION),
        read_permission: text(element, attr::READ_PERMISSION),
        write_permission: text(element, attr::WRITE_PERMISSION),
        authorities: authorities(element),
        grant_uri_permissions: boolean(element, attr::GRANT_URI_PERMISSIONS),
        process: text(element, attr::PROCESS),
        target_activity: text(element, attr::TARGET_ACTIVITY),
        intent_filters: element
            .elements_named("intent-filter")
            .map(read_intent_filter)
            .collect(),
        meta_data: element
            .elements_named("meta-data")
            .filter_map(read_meta_data)
            .collect(),
    })
}

fn read_intent_filter(element: &XmlElement) -> IntentFilter {
    IntentFilter {
        actions: element
            .elements_named("action")
            .filter_map(|action| text(action, attr::NAME))
            .collect(),
        categories: element
            .elements_named("category")
            .filter_map(|category| text(category, attr::NAME))
            .collect(),
        data: element
            .elements_named("data")
            .map(read_intent_data)
            .collect(),
        auto_verify: boolean(element, attr::AUTO_VERIFY),
        priority: integer(element, attr::PRIORITY),
    }
}

fn read_intent_data(element: &XmlElement) -> IntentData {
    IntentData {
        scheme: text(element, attr::SCHEME),
        host: text(element, attr::HOST),
        port: text(element, attr::PORT),
        path: text(element, attr::PATH),
        path_prefix: text(element, attr::PATH_PREFIX),
        path_pattern: text(element, attr::PATH_PATTERN),
        path_suffix: text(element, attr::PATH_SUFFIX),
        path_advanced_pattern: text(element, attr::PATH_ADVANCED_PATTERN),
        mime_type: text(element, attr::MIME_TYPE),
    }
}

fn read_meta_data(element: &XmlElement) -> Option<MetaData> {
    Some(MetaData {
        name: text(element, attr::NAME)?,
        value: element.attribute(attr::VALUE).cloned(),
        resource: element.attribute(attr::RESOURCE).cloned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android::xml::framework_attribute_name;

    /// Every constant above names the attribute the Android SDK assigns that ID to.
    #[test]
    fn attribute_constants_match_the_sdk() {
        let expected = [
            (attr::LABEL, "label"),
            (attr::ICON, "icon"),
            (attr::NAME, "name"),
            (attr::PERMISSION, "permission"),
            (attr::READ_PERMISSION, "readPermission"),
            (attr::WRITE_PERMISSION, "writePermission"),
            (attr::PROTECTION_LEVEL, "protectionLevel"),
            (attr::PERMISSION_GROUP, "permissionGroup"),
            (attr::SHARED_USER_ID, "sharedUserId"),
            (attr::ENABLED, "enabled"),
            (attr::DEBUGGABLE, "debuggable"),
            (attr::EXPORTED, "exported"),
            (attr::PROCESS, "process"),
            (attr::AUTHORITIES, "authorities"),
            (attr::GRANT_URI_PERMISSIONS, "grantUriPermissions"),
            (attr::PRIORITY, "priority"),
            (attr::VALUE, "value"),
            (attr::RESOURCE, "resource"),
            (attr::MIME_TYPE, "mimeType"),
            (attr::SCHEME, "scheme"),
            (attr::HOST, "host"),
            (attr::PORT, "port"),
            (attr::PATH, "path"),
            (attr::PATH_PREFIX, "pathPrefix"),
            (attr::PATH_PATTERN, "pathPattern"),
            (attr::TARGET_ACTIVITY, "targetActivity"),
            (attr::MIN_SDK_VERSION, "minSdkVersion"),
            (attr::VERSION_CODE, "versionCode"),
            (attr::VERSION_NAME, "versionName"),
            (attr::ANY_DENSITY, "anyDensity"),
            (attr::TARGET_SDK_VERSION, "targetSdkVersion"),
            (attr::MAX_SDK_VERSION, "maxSdkVersion"),
            (attr::TEST_ONLY, "testOnly"),
            (attr::BACKUP_AGENT, "backupAgent"),
            (attr::ALLOW_BACKUP, "allowBackup"),
            (attr::GL_ES_VERSION, "glEsVersion"),
            (attr::SMALL_SCREENS, "smallScreens"),
            (attr::NORMAL_SCREENS, "normalScreens"),
            (attr::LARGE_SCREENS, "largeScreens"),
            (attr::RESIZEABLE, "resizeable"),
            (attr::REQUIRED, "required"),
            (attr::INSTALL_LOCATION, "installLocation"),
            (attr::XLARGE_SCREENS, "xlargeScreens"),
            (attr::LARGE_HEAP, "largeHeap"),
            (attr::REQUIRES_SMALLEST_WIDTH_DP, "requiresSmallestWidthDp"),
            (attr::EXTRACT_NATIVE_LIBS, "extractNativeLibs"),
            (attr::FULL_BACKUP_CONTENT, "fullBackupContent"),
            (attr::USES_CLEARTEXT_TRAFFIC, "usesCleartextTraffic"),
            (attr::AUTO_VERIFY, "autoVerify"),
            (attr::NETWORK_SECURITY_CONFIG, "networkSecurityConfig"),
            (attr::ROUND_ICON, "roundIcon"),
            (attr::COMPILE_SDK_VERSION, "compileSdkVersion"),
            (
                attr::COMPILE_SDK_VERSION_CODENAME,
                "compileSdkVersionCodename",
            ),
            (attr::VERSION_CODE_MAJOR, "versionCodeMajor"),
            (attr::APP_COMPONENT_FACTORY, "appComponentFactory"),
            (attr::HAS_FRAGILE_USER_DATA, "hasFragileUserData"),
            (
                attr::REQUEST_LEGACY_EXTERNAL_STORAGE,
                "requestLegacyExternalStorage",
            ),
            (attr::PATH_SUFFIX, "pathSuffix"),
            (attr::PATH_ADVANCED_PATTERN, "pathAdvancedPattern"),
            (attr::DATA_EXTRACTION_RULES, "dataExtractionRules"),
            (attr::USES_PERMISSION_FLAGS, "usesPermissionFlags"),
        ];
        for (id, name) in expected {
            assert_eq!(framework_attribute_name(id), Some(name), "0x{id:08x}");
        }
    }

    #[test]
    fn class_names_expand_like_the_package_parser() {
        assert_eq!(class_name("com.app", ".Main"), "com.app.Main");
        assert_eq!(class_name("com.app", "Main"), "com.app.Main");
        assert_eq!(class_name("com.app", "org.lib.Service"), "org.lib.Service");
    }

    #[test]
    fn sdk_levels_accept_numbers_and_codenames() {
        assert_eq!(
            SdkLevel::from_value(&Value::Integer(24)),
            Some(SdkLevel::Api(24))
        );
        assert_eq!(
            SdkLevel::from_value(&Value::String(Some("34".into()))),
            Some(SdkLevel::Api(34))
        );
        assert_eq!(
            SdkLevel::from_value(&Value::String(Some("Baklava".into()))),
            Some(SdkLevel::Codename("Baklava".into()))
        );
    }
}
