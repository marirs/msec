//! Privacy manifests (`PrivacyInfo.xcprivacy`): what each bundle declares about tracking, the
//! data it collects and the required-reason APIs it uses, read with every structural problem
//! named (the kind of problem App Store Connect reports as ITMS-91056, invalid privacy
//! manifest).

use crate::plist::{Dictionary, Value};

/// A privacy manifest, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyManifest {
    /// Its path in the archive.
    pub path: String,
    /// Why it could not be read as a plist, when it could not.
    pub problem: Option<String>,
    /// `NSPrivacyTracking`: the code this manifest covers uses data for tracking.
    pub tracking: Option<bool>,
    /// `NSPrivacyTrackingDomains`: the domains it connects to for tracking, which iOS blocks
    /// until the user allows tracking.
    pub tracking_domains: Vec<String>,
    /// `NSPrivacyCollectedDataTypes`: each type of data collected.
    pub collected_data_types: Vec<CollectedDataType>,
    /// `NSPrivacyAccessedAPITypes`: each required-reason API category used, with its reasons.
    pub accessed_api_types: Vec<AccessedApiType>,
    /// The manifest has an `NSPrivacyAccessedAPITypes` key (an empty array is invalid).
    pub declares_accessed_api_types: bool,
    /// What does not have the structure Apple documents: a key of the wrong type, an entry
    /// without its required keys, a root that is not a dictionary. Values are checked against
    /// Apple's lists by [`super::required_reason::manifest_problems`].
    pub structure_problems: Vec<String>,
}

/// One `NSPrivacyCollectedDataTypes` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedDataType {
    /// `NSPrivacyCollectedDataType` (`NSPrivacyCollectedDataTypeEmailAddress`).
    pub data_type: Option<String>,
    /// `NSPrivacyCollectedDataTypeLinked`: linked to the user's identity.
    pub linked: Option<bool>,
    /// `NSPrivacyCollectedDataTypeTracking`: used for tracking.
    pub tracking: Option<bool>,
    /// `NSPrivacyCollectedDataTypePurposes`.
    pub purposes: Vec<String>,
}

/// One `NSPrivacyAccessedAPITypes` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessedApiType {
    /// `NSPrivacyAccessedAPIType` (`NSPrivacyAccessedAPICategoryUserDefaults`).
    pub category: Option<String>,
    /// `NSPrivacyAccessedAPITypeReasons` (`CA92.1`).
    pub reasons: Vec<String>,
}

impl PrivacyManifest {
    /// Reads a manifest from its parsed root (`Err`: why the plist could not be read).
    pub fn read(path: String, root: Result<&Value, String>) -> Self {
        let mut manifest = Self {
            path,
            problem: None,
            tracking: None,
            tracking_domains: Vec::new(),
            collected_data_types: Vec::new(),
            accessed_api_types: Vec::new(),
            declares_accessed_api_types: false,
            structure_problems: Vec::new(),
        };
        let root = match root {
            Ok(root) => root,
            Err(problem) => {
                manifest.problem = Some(problem);
                return manifest;
            }
        };
        let Some(dictionary) = root.as_dictionary() else {
            manifest
                .structure_problems
                .push("the root is not a dictionary".to_owned());
            return manifest;
        };
        let mut problems = Vec::new();
        manifest.tracking = boolean(dictionary, "NSPrivacyTracking", "", &mut problems);
        manifest.tracking_domains =
            strings(dictionary, "NSPrivacyTrackingDomains", "", &mut problems);
        for (index, entry) in entries(dictionary, "NSPrivacyCollectedDataTypes", &mut problems) {
            let at = format!("NSPrivacyCollectedDataTypes[{index}]");
            let data_type =
                required_string(entry, "NSPrivacyCollectedDataType", &at, &mut problems);
            manifest.collected_data_types.push(CollectedDataType {
                data_type,
                linked: required_boolean(
                    entry,
                    "NSPrivacyCollectedDataTypeLinked",
                    &at,
                    &mut problems,
                ),
                tracking: required_boolean(
                    entry,
                    "NSPrivacyCollectedDataTypeTracking",
                    &at,
                    &mut problems,
                ),
                purposes: required_strings(
                    entry,
                    "NSPrivacyCollectedDataTypePurposes",
                    &at,
                    &mut problems,
                ),
            });
        }
        manifest.declares_accessed_api_types =
            dictionary.get("NSPrivacyAccessedAPITypes").is_some();
        for (index, entry) in entries(dictionary, "NSPrivacyAccessedAPITypes", &mut problems) {
            let at = format!("NSPrivacyAccessedAPITypes[{index}]");
            manifest.accessed_api_types.push(AccessedApiType {
                category: required_string(entry, "NSPrivacyAccessedAPIType", &at, &mut problems),
                reasons: required_strings(
                    entry,
                    "NSPrivacyAccessedAPITypeReasons",
                    &at,
                    &mut problems,
                ),
            });
        }
        manifest.structure_problems = problems;
        manifest
    }
}

fn place(at: &str, key: &str) -> String {
    if at.is_empty() {
        key.to_owned()
    } else {
        format!("{at}.{key}")
    }
}

fn boolean(
    dictionary: &Dictionary,
    key: &str,
    at: &str,
    problems: &mut Vec<String>,
) -> Option<bool> {
    let value = dictionary.get(key)?;
    let flag = value.as_bool();
    if flag.is_none() {
        problems.push(format!("{} is not a boolean", place(at, key)));
    }
    flag
}

fn required_boolean(
    dictionary: &Dictionary,
    key: &str,
    at: &str,
    problems: &mut Vec<String>,
) -> Option<bool> {
    if dictionary.get(key).is_none() {
        problems.push(format!("{} is missing", place(at, key)));
    }
    boolean(dictionary, key, at, problems)
}

fn required_string(
    dictionary: &Dictionary,
    key: &str,
    at: &str,
    problems: &mut Vec<String>,
) -> Option<String> {
    match dictionary.get(key) {
        None => {
            problems.push(format!("{} is missing", place(at, key)));
            None
        }
        Some(value) => match value.as_str() {
            Some(text) => Some(text.to_owned()),
            None => {
                problems.push(format!("{} is not a string", place(at, key)));
                None
            }
        },
    }
}

/// An array of strings; entries that are not strings are named and left out.
fn strings(
    dictionary: &Dictionary,
    key: &str,
    at: &str,
    problems: &mut Vec<String>,
) -> Vec<String> {
    let Some(value) = dictionary.get(key) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        problems.push(format!("{} is not an array", place(at, key)));
        return Vec::new();
    };
    let mut found = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match item.as_str() {
            Some(text) => found.push(text.to_owned()),
            None => problems.push(format!("{}[{index}] is not a string", place(at, key))),
        }
    }
    found
}

fn required_strings(
    dictionary: &Dictionary,
    key: &str,
    at: &str,
    problems: &mut Vec<String>,
) -> Vec<String> {
    if dictionary.get(key).is_none() {
        problems.push(format!("{} is missing", place(at, key)));
    }
    strings(dictionary, key, at, problems)
}

/// The dictionaries of an array of dictionaries, with their indexes; anything else is named.
fn entries<'value>(
    dictionary: &'value Dictionary,
    key: &str,
    problems: &mut Vec<String>,
) -> Vec<(usize, &'value Dictionary)> {
    let Some(value) = dictionary.get(key) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        problems.push(format!("{key} is not an array"));
        return Vec::new();
    };
    let mut found = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match item.as_dictionary() {
            Some(entry) => found.push((index, entry)),
            None => problems.push(format!("{key}[{index}] is not a dictionary")),
        }
    }
    found
}
