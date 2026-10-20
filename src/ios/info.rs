//! What a bundle's `Info.plist` declares, as typed fields. A key present with the wrong type
//! (a bundle identifier written as an integer) is not silently dropped: it is listed in
//! [`BundleInfo::wrong_types`], because iOS and analysis tools then read different things.

use crate::plist::{Dictionary, Value};

/// Keys of `Info.plist` msec reads, with the value each holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleInfo {
    /// `CFBundleIdentifier`.
    pub identifier: Option<String>,
    /// `CFBundleName`.
    pub name: Option<String>,
    /// `CFBundleDisplayName`.
    pub display_name: Option<String>,
    /// `CFBundleExecutable`: the main executable's file name in the bundle.
    pub executable: Option<String>,
    /// `CFBundleShortVersionString` (the marketing version).
    pub short_version: Option<String>,
    /// `CFBundleVersion` (the build number).
    pub version: Option<String>,
    /// `CFBundlePackageType` (`APPL`, `FMWK`, `XPC!`).
    pub package_type: Option<String>,
    /// `MinimumOSVersion`.
    pub minimum_os_version: Option<String>,
    /// `DTPlatformName` (`iphoneos`), written by Xcode.
    pub platform_name: Option<String>,
    /// `DTSDKName` (`iphoneos27.1`).
    pub sdk_name: Option<String>,
    /// `DTXcode` (`2710` for Xcode 27.1).
    pub xcode: Option<String>,
    /// `CFBundleSupportedPlatforms`.
    pub supported_platforms: Vec<String>,
    /// `UIDeviceFamily`: 1 iPhone, 2 iPad, 3 Apple TV, 4 Apple Watch, 7 Apple Vision.
    pub device_families: Vec<i64>,
    /// `UIRequiredDeviceCapabilities`: an array, or the keys of a dictionary whose value is
    /// true.
    pub required_capabilities: Vec<String>,
    /// URL schemes the app handles (`CFBundleURLTypes`, every `CFBundleURLSchemes`).
    pub url_schemes: Vec<String>,
    /// URL schemes the app may query (`LSApplicationQueriesSchemes`).
    pub queried_schemes: Vec<String>,
    /// `UIBackgroundModes`.
    pub background_modes: Vec<String>,
    /// Purpose strings for protected resources: every top-level `NS...UsageDescription` key
    /// with its text, sorted by key.
    pub usage_descriptions: Vec<(String, String)>,
    /// `ITSAppUsesNonExemptEncryption`.
    pub uses_non_exempt_encryption: Option<bool>,
    /// `UIFileSharingEnabled`: the app's Documents folder is visible in Finder and Files.
    pub file_sharing: Option<bool>,
    /// `LSSupportsOpeningDocumentsInPlace`.
    pub opens_documents_in_place: Option<bool>,
    /// `NSExtension` / `NSExtensionPointIdentifier`, for app extensions.
    pub extension_point: Option<String>,
    /// Keys present with a type other than the one iOS reads them as.
    pub wrong_types: Vec<WrongType>,
}

/// A key whose value has an unexpected type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongType {
    /// The key (`CFBundleIdentifier`, or `NSExtension/NSExtensionPointIdentifier`).
    pub key: String,
    /// The type iOS reads it as.
    pub expected: &'static str,
    /// The type it has.
    pub found: &'static str,
}

impl BundleInfo {
    /// Reads the fields from an `Info.plist` dictionary.
    pub fn of(dictionary: &Dictionary) -> Self {
        let mut reader = Reader {
            dictionary,
            wrong_types: Vec::new(),
        };
        let mut info = BundleInfo {
            identifier: reader.string("CFBundleIdentifier"),
            name: reader.string("CFBundleName"),
            display_name: reader.string("CFBundleDisplayName"),
            executable: reader.string("CFBundleExecutable"),
            short_version: reader.string("CFBundleShortVersionString"),
            version: reader.string("CFBundleVersion"),
            package_type: reader.string("CFBundlePackageType"),
            minimum_os_version: reader.string("MinimumOSVersion"),
            platform_name: reader.string("DTPlatformName"),
            sdk_name: reader.string("DTSDKName"),
            xcode: reader.string("DTXcode"),
            supported_platforms: reader.strings("CFBundleSupportedPlatforms"),
            device_families: reader.integers("UIDeviceFamily"),
            required_capabilities: reader.capabilities(),
            url_schemes: reader.url_schemes(),
            queried_schemes: reader.strings("LSApplicationQueriesSchemes"),
            background_modes: reader.strings("UIBackgroundModes"),
            usage_descriptions: reader.usage_descriptions(),
            uses_non_exempt_encryption: reader.boolean("ITSAppUsesNonExemptEncryption"),
            file_sharing: reader.boolean("UIFileSharingEnabled"),
            opens_documents_in_place: reader.boolean("LSSupportsOpeningDocumentsInPlace"),
            extension_point: reader.extension_point(),
            wrong_types: Vec::new(),
        };
        info.wrong_types = reader.wrong_types;
        info
    }
}

struct Reader<'a> {
    dictionary: &'a Dictionary,
    wrong_types: Vec<WrongType>,
}

impl Reader<'_> {
    fn wrong(&mut self, key: &str, expected: &'static str, found: &Value) {
        self.wrong_types.push(WrongType {
            key: key.to_owned(),
            expected,
            found: found.type_name(),
        });
    }

    fn string(&mut self, key: &str) -> Option<String> {
        let value = self.dictionary.get(key)?;
        match value.as_str() {
            Some(text) => Some(text.to_owned()),
            None => {
                self.wrong(key, "string", value);
                None
            }
        }
    }

    fn boolean(&mut self, key: &str) -> Option<bool> {
        let value = self.dictionary.get(key)?;
        match value.as_bool() {
            Some(flag) => Some(flag),
            None => {
                self.wrong(key, "boolean", value);
                None
            }
        }
    }

    /// An array of strings; items of another type are listed as wrong.
    fn strings(&mut self, key: &str) -> Vec<String> {
        let Some(value) = self.dictionary.get(key) else {
            return Vec::new();
        };
        let Some(items) = value.as_array() else {
            self.wrong(key, "array", value);
            return Vec::new();
        };
        let mut strings = Vec::new();
        for (index, item) in items.iter().enumerate() {
            match item.as_str() {
                Some(text) => strings.push(text.to_owned()),
                None => self.wrong(&format!("{key}/{index}"), "string", item),
            }
        }
        strings
    }

    fn integers(&mut self, key: &str) -> Vec<i64> {
        let Some(value) = self.dictionary.get(key) else {
            return Vec::new();
        };
        let Some(items) = value.as_array() else {
            self.wrong(key, "array", value);
            return Vec::new();
        };
        let mut integers = Vec::new();
        for (index, item) in items.iter().enumerate() {
            match item
                .as_integer()
                .and_then(|number| i64::try_from(number).ok())
            {
                Some(number) => integers.push(number),
                None => self.wrong(&format!("{key}/{index}"), "integer", item),
            }
        }
        integers
    }

    fn capabilities(&mut self) -> Vec<String> {
        const KEY: &str = "UIRequiredDeviceCapabilities";
        match self.dictionary.get(KEY) {
            Some(Value::Dictionary(capabilities)) => capabilities
                .iter()
                .filter(|(_, required)| required.as_bool() == Some(true))
                .map(|(name, _)| name.to_owned())
                .collect(),
            _ => self.strings(KEY),
        }
    }

    fn url_schemes(&mut self) -> Vec<String> {
        const KEY: &str = "CFBundleURLTypes";
        let Some(value) = self.dictionary.get(KEY) else {
            return Vec::new();
        };
        let Some(types) = value.as_array() else {
            self.wrong(KEY, "array", value);
            return Vec::new();
        };
        let mut schemes = Vec::new();
        for (index, url_type) in types.iter().enumerate() {
            let Some(url_type) = url_type.as_dictionary() else {
                self.wrong(&format!("{KEY}/{index}"), "dict", url_type);
                continue;
            };
            let mut inner = Reader {
                dictionary: url_type,
                wrong_types: Vec::new(),
            };
            schemes.extend(inner.strings("CFBundleURLSchemes"));
            self.wrong_types
                .extend(inner.wrong_types.into_iter().map(|mut wrong| {
                    wrong.key = format!("{KEY}/{index}/{}", wrong.key);
                    wrong
                }));
        }
        schemes
    }

    fn usage_descriptions(&mut self) -> Vec<(String, String)> {
        let mut descriptions: Vec<(String, String)> = Vec::new();
        for (key, value) in self.dictionary.iter() {
            if !(key.starts_with("NS") && key.ends_with("UsageDescription")) {
                continue;
            }
            match value.as_str() {
                Some(text) => descriptions.push((key.to_owned(), text.to_owned())),
                None => self.wrong(key, "string", value),
            }
        }
        descriptions.sort();
        descriptions
    }

    fn extension_point(&mut self) -> Option<String> {
        let extension = self.dictionary.get("NSExtension")?;
        let Some(extension) = extension.as_dictionary() else {
            self.wrong("NSExtension", "dict", extension);
            return None;
        };
        let point = extension.get("NSExtensionPointIdentifier")?;
        match point.as_str() {
            Some(text) => Some(text.to_owned()),
            None => {
                self.wrong("NSExtension/NSExtensionPointIdentifier", "string", point);
                None
            }
        }
    }
}
