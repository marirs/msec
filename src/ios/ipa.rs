//! Locating the app bundle in an IPA and inventorying it.

use std::collections::BTreeSet;
use std::io::{Read, Seek};

use super::ats::TransportSecurity;
use super::binaries::{BinaryRole, BundleBinary, read_binary};
use super::info::BundleInfo;
use super::privacy::PrivacyManifest;
use super::profile::{ProfileError, ProvisioningProfile};
use crate::archive::{ArchiveError, ZipArchive};
use crate::plist::{self, Plist, PlistError, Value};

/// Largest `Info.plist` or privacy manifest read; real ones are a few kilobytes.
const MAX_PLIST_BYTES: u64 = 8 * 1024 * 1024;
const PAYLOAD: &str = "Payload/";
const APP_SUFFIX: &str = ".app";

/// An IPA read in full: its app bundle, and what is wrong with the package's layout.
#[derive(Debug, Clone, PartialEq)]
pub struct Ipa {
    /// The app bundle, when one was found.
    pub app: Option<AppBundle>,
    /// Layout problems.
    pub problems: Vec<IpaProblem>,
    /// `iTunesMetadata.plist` at the archive root: the IPA was downloaded from the App Store
    /// (or repackaged from such a download).
    pub itunes_metadata: bool,
    /// `SwiftSupport/` at the archive root, as Xcode exports it for the App Store.
    pub swift_support: bool,
    /// `Symbols/` at the archive root (symbol files uploaded with the app).
    pub symbols: bool,
}

/// What is wrong with an IPA's layout or its bundle's `Info.plist`.
#[derive(Debug, Clone, PartialEq)]
pub enum IpaProblem {
    /// No `.app` directory anywhere.
    NoAppBundle,
    /// More than one `Payload/<name>.app/`; the first in the archive is analysed.
    MultipleAppBundles(Vec<String>),
    /// The app bundle is not at `Payload/<name>.app/` but elsewhere (MobSF accepts any depth;
    /// App Store tooling expects the root).
    AppBundleNotAtPayloadRoot(String),
    /// The bundle has no `Info.plist`.
    InfoPlistMissing,
    /// `Info.plist` is larger than msec reads.
    InfoPlistTooLarge(u64),
    /// `Info.plist` could not be read from the archive.
    InfoPlistUnreadable(String),
    /// `Info.plist` is not a plist iOS reads.
    InfoPlistInvalid(PlistError),
    /// `Info.plist`'s top level is not a dictionary.
    InfoPlistNotDictionary(&'static str),
    /// `Info.plist` names top-level keys more than once. iOS reads binary plists keeping the
    /// first value and XML ones keeping the last; on the simulator, a binary `Info.plist` with
    /// two different `CFBundleIdentifier` values is refused ("Mismatched bundle IDs"), so parts
    /// of iOS itself read it differently.
    InfoPlistDuplicateKeys(Vec<String>),
    /// `CFBundleIdentifier` is missing or not a string.
    IdentifierMissing,
    /// `CFBundleExecutable` is missing.
    ExecutableNotDeclared,
    /// `CFBundleExecutable` is not a plain file name (empty, `.`, `..`, or with a `/`).
    ExecutableNameInvalid(String),
    /// The executable `CFBundleExecutable` names is not in the bundle.
    ExecutableMissing(String),
}

impl IpaProblem {
    /// iOS's installer refuses a bundle with this problem. Checked on the simulator's
    /// installer for each kind it can be shown (tests/fixtures/ios/install-verdicts.txt);
    /// false for archive layouts, which only device and App Store installs see, and for
    /// duplicate keys, where the outcome depends on the key and the format.
    pub fn rejected_by_ios(&self) -> bool {
        match self {
            Self::NoAppBundle
            | Self::InfoPlistMissing
            | Self::InfoPlistUnreadable(_)
            | Self::InfoPlistInvalid(_)
            | Self::InfoPlistNotDictionary(_)
            | Self::IdentifierMissing
            | Self::ExecutableNotDeclared
            | Self::ExecutableNameInvalid(_)
            | Self::ExecutableMissing(_) => true,
            Self::MultipleAppBundles(_)
            | Self::AppBundleNotAtPayloadRoot(_)
            | Self::InfoPlistTooLarge(_)
            | Self::InfoPlistDuplicateKeys(_) => false,
        }
    }
}

/// The app bundle (`Payload/<name>.app/`).
#[derive(Debug, Clone, PartialEq)]
pub struct AppBundle {
    /// Its directory in the archive, with a trailing slash.
    pub path: String,
    /// `Info.plist`, read in full, when it was read.
    pub info_plist: Option<Plist>,
    /// The fields msec reads from it.
    pub info: Option<BundleInfo>,
    /// The main executable's path in the archive, when `CFBundleExecutable` names a file the
    /// bundle has.
    pub executable: Option<String>,
    /// Frameworks, loose libraries, app extensions, watch apps and App Clips inside.
    pub components: Vec<BundleComponent>,
    /// Every `PrivacyInfo.xcprivacy` in the bundle (the app's, and its frameworks' and
    /// resource bundles').
    pub privacy_manifests: Vec<PrivacyManifest>,
    /// `embedded.mobileprovision`: the provisioning profile (absent from App Store
    /// downloads).
    pub provisioning_profile: Option<String>,
    /// That profile, read.
    pub profile: Option<Result<ProvisioningProfile, ProfileError>>,
    /// `NSAppTransportSecurity`, read from `Info.plist`.
    pub transport_security: Option<TransportSecurity>,
    /// `_CodeSignature/CodeResources`: the code signature's seal of the bundle's resources.
    pub code_resources: Option<String>,
    /// `SC_Info/`: FairPlay metadata, present when the App Store encrypted the executables.
    pub fairplay_metadata: bool,
    /// Localizations (`<language>.lproj` directories at the bundle root), sorted.
    pub localizations: Vec<String>,
    /// Every `<language>.lproj/InfoPlist.strings` of the app and of its app extensions, watch
    /// apps and App Clips (what iOS shows instead of `Info.plist` values in that language), in
    /// archive order. Frameworks' are left out: their `Info.plist` holds no purpose strings.
    pub localized_info: Vec<LocalizedInfo>,
    /// The main executable and every component's executable, read as Mach-O with their
    /// signatures checked; main executable first.
    pub binaries: Vec<BundleBinary>,
    /// Files in the bundle, nested components included.
    pub file_count: usize,
    /// Their uncompressed size, as the archive declares it.
    pub declared_bytes: u64,
}

/// One `InfoPlist.strings`: localized `Info.plist` values.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalizedInfo {
    /// Its path in the archive (`Payload/A.app/fr.lproj/InfoPlist.strings`).
    pub path: String,
    /// The bundle it localizes: a directory with a trailing slash.
    pub bundle: String,
    /// The language (`fr`, `pt-BR`).
    pub language: String,
    /// The values by key, or why the file could not be read (Xcode writes a binary plist;
    /// other toolchains ship `.strings` text, which is read too).
    pub strings: Result<crate::plist::Dictionary, String>,
}

/// A bundle or library inside the app bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleComponent {
    /// What it is.
    pub kind: ComponentKind,
    /// Its path in the archive (a directory with a trailing slash, or a library file).
    pub path: String,
    /// Its `Info.plist` fields, for bundles that have one.
    pub info: Option<BundleInfo>,
    /// Why its `Info.plist` was not read, for a bundle without usable one.
    pub info_problem: Option<String>,
    /// Its executable's path, when found.
    pub executable: Option<String>,
}

/// Kinds of [`BundleComponent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ComponentKind {
    /// `Frameworks/<name>.framework/`.
    Framework,
    /// `Frameworks/<name>.dylib`.
    Library,
    /// `PlugIns/<name>.appex/`.
    AppExtension,
    /// `Extensions/<name>.appex/` (ExtensionKit).
    ExtensionKitExtension,
    /// `Watch/<name>.app/`.
    WatchApp,
    /// `AppClips/<name>.app/`.
    AppClip,
}

impl ComponentKind {
    /// In words.
    pub fn label(self) -> &'static str {
        match self {
            Self::Framework => "framework",
            Self::Library => "library",
            Self::AppExtension => "app extension",
            Self::ExtensionKitExtension => "ExtensionKit extension",
            Self::WatchApp => "watch app",
            Self::AppClip => "App Clip",
        }
    }
}

impl Ipa {
    /// Reads an IPA: locates the app bundle and reads what it declares.
    pub fn read<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Self {
        let names: Vec<String> = archive
            .entries()
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        let at_root = |prefix: &str| names.iter().any(|name| name.starts_with(prefix));
        let mut ipa = Ipa {
            app: None,
            problems: Vec::new(),
            itunes_metadata: names.iter().any(|name| name == "iTunesMetadata.plist"),
            swift_support: at_root("SwiftSupport/"),
            symbols: at_root("Symbols/"),
        };
        let Some(path) = locate_app_bundle(&names, &mut ipa.problems) else {
            ipa.problems.push(IpaProblem::NoAppBundle);
            return ipa;
        };
        ipa.app = Some(read_app_bundle(archive, &names, path, &mut ipa.problems));
        ipa
    }
}

/// `Payload/<name>.app/`, the first in the archive when there are several; otherwise the
/// shallowest `<name>.app/` anywhere, recorded as a problem.
fn locate_app_bundle(names: &[String], problems: &mut Vec<IpaProblem>) -> Option<String> {
    let mut at_root: Vec<String> = Vec::new();
    for name in names {
        let Some(rest) = name.strip_prefix(PAYLOAD) else {
            continue;
        };
        let Some((bundle, _)) = rest.split_once('/') else {
            continue;
        };
        if bundle.len() > APP_SUFFIX.len() && bundle.ends_with(APP_SUFFIX) {
            let path = format!("{PAYLOAD}{bundle}/");
            if !at_root.contains(&path) {
                at_root.push(path);
            }
        }
    }
    if at_root.len() > 1 {
        problems.push(IpaProblem::MultipleAppBundles(at_root.clone()));
    }
    if let Some(first) = at_root.into_iter().next() {
        return Some(first);
    }
    let nested = names
        .iter()
        .filter_map(|name| {
            let segments: Vec<&str> = name.split('/').collect();
            let position = segments[..segments.len().saturating_sub(1)]
                .iter()
                .position(|segment| {
                    segment.len() > APP_SUFFIX.len() && segment.ends_with(APP_SUFFIX)
                })?;
            Some(format!("{}/", segments[..=position].join("/")))
        })
        .min_by_key(|path| (path.matches('/').count(), path.clone()))?;
    problems.push(IpaProblem::AppBundleNotAtPayloadRoot(nested.clone()));
    Some(nested)
}

fn read_app_bundle<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    names: &[String],
    path: String,
    problems: &mut Vec<IpaProblem>,
) -> AppBundle {
    let inside: Vec<&str> = names
        .iter()
        .filter_map(|name| name.strip_prefix(path.as_str()))
        .collect();
    let has = |relative: &str| inside.contains(&relative);
    let files: Vec<&crate::archive::Entry> = archive
        .entries()
        .iter()
        .filter(|entry| entry.name.starts_with(&path) && !entry.is_directory)
        .collect();
    let file_count = files.len();
    let declared_bytes = files.iter().map(|entry| entry.uncompressed_size).sum();

    let info_plist = read_info_plist(archive, &format!("{path}Info.plist"), problems);
    let info = info_plist.as_ref().and_then(|plist| match &plist.root {
        plist::Value::Dictionary(dictionary) => Some(BundleInfo::of(dictionary)),
        other => {
            problems.push(IpaProblem::InfoPlistNotDictionary(other.type_name()));
            None
        }
    });
    if let Some(plist) = &info_plist {
        let duplicates: Vec<String> = plist
            .anomalies
            .iter()
            .filter_map(|anomaly| match anomaly {
                plist::Anomaly::DuplicateKey { path, key } if path == "/" => Some(key.clone()),
                _ => None,
            })
            .collect();
        if !duplicates.is_empty() {
            problems.push(IpaProblem::InfoPlistDuplicateKeys(duplicates));
        }
    }
    if info.as_ref().is_some_and(|info| info.identifier.is_none()) {
        problems.push(IpaProblem::IdentifierMissing);
    }
    let executable = info
        .as_ref()
        .and_then(|info| main_executable(info, &path, &has, problems));
    let components = components(archive, &inside, &path);
    let privacy_manifests = inside
        .iter()
        .filter(|relative| {
            *relative == &"PrivacyInfo.xcprivacy" || relative.ends_with("/PrivacyInfo.xcprivacy")
        })
        .map(|relative| {
            let manifest = format!("{path}{relative}");
            let (problem, root) = match read_plist(archive, &manifest) {
                Ok(parsed) => (None, Some(parsed.root)),
                Err(problem) => (Some(problem), None),
            };
            PrivacyManifest::read(
                manifest,
                root.as_ref()
                    .ok_or_else(|| problem.clone().unwrap_or_default()),
            )
        })
        .collect();
    let localizations: BTreeSet<String> = inside
        .iter()
        .filter_map(|relative| relative.split_once('/'))
        .filter_map(|(directory, _)| directory.strip_suffix(".lproj"))
        .filter(|language| !language.is_empty())
        .map(str::to_owned)
        .collect();
    let localized_info = localized_info(archive, &inside, &path);
    let profile_path = format!("{path}embedded.mobileprovision");
    let profile = archive
        .find(&profile_path)
        .map(|entry| entry.index)
        .map(|index| match archive.read(index) {
            Ok(bytes) => ProvisioningProfile::parse(&bytes),
            Err(error) => Err(ProfileError::Unreadable(error.to_string())),
        });
    let transport_security = info_plist
        .as_ref()
        .and_then(|plist| plist.root.as_dictionary())
        .map(TransportSecurity::of);
    let mut binaries = Vec::new();
    if let Some(executable) = &executable {
        binaries.push(read_binary(
            archive,
            executable,
            BinaryRole::MainExecutable,
            &path,
        ));
    }
    for component in &components {
        let Some(executable) = &component.executable else {
            continue;
        };
        // A loose library is sealed by the app; a bundle by its own Info.plist and resources.
        let bundle = if component.kind == ComponentKind::Library {
            path.as_str()
        } else {
            component.path.as_str()
        };
        binaries.push(read_binary(
            archive,
            executable,
            BinaryRole::Component(component.kind),
            bundle,
        ));
    }
    AppBundle {
        info_plist,
        info,
        executable,
        components,
        binaries,
        privacy_manifests,
        provisioning_profile: has("embedded.mobileprovision").then_some(profile_path),
        profile,
        transport_security,
        code_resources: has("_CodeSignature/CodeResources")
            .then(|| format!("{path}_CodeSignature/CodeResources")),
        fairplay_metadata: inside
            .iter()
            .any(|relative| relative.starts_with("SC_Info/")),
        localizations: localizations.into_iter().collect(),
        localized_info,
        file_count,
        declared_bytes,
        path,
    }
}

fn read_info_plist<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    problems: &mut Vec<IpaProblem>,
) -> Option<Plist> {
    let Some(entry) = archive.find(name) else {
        problems.push(IpaProblem::InfoPlistMissing);
        return None;
    };
    if entry.uncompressed_size > MAX_PLIST_BYTES {
        problems.push(IpaProblem::InfoPlistTooLarge(entry.uncompressed_size));
        return None;
    }
    let bytes = match archive.read(entry.index) {
        Ok(bytes) => bytes,
        Err(error) => {
            problems.push(IpaProblem::InfoPlistUnreadable(error.to_string()));
            return None;
        }
    };
    match plist::parse(&bytes) {
        Ok(plist) => Some(plist),
        Err(error) => {
            problems.push(IpaProblem::InfoPlistInvalid(error));
            None
        }
    }
}

/// A plist inside the bundle, or why it could not be read.
/// The `InfoPlist.strings` of the app (`path`) and of the bundles inside it that have their
/// own purpose strings (`.appex`, watch apps, App Clips); `inside` lists the app's files
/// relative to `path`.
fn localized_info<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    inside: &[&str],
    path: &str,
) -> Vec<LocalizedInfo> {
    let mut found = Vec::new();
    for relative in inside {
        let Some(directory) = relative.strip_suffix(".lproj/InfoPlist.strings") else {
            continue;
        };
        let (bundle, language) = match directory.rsplit_once('/') {
            Some((bundle, language)) => (format!("{bundle}/"), language),
            None => (String::new(), directory),
        };
        let own_purpose_strings =
            bundle.is_empty() || bundle.ends_with(".appex/") || bundle.ends_with(".app/");
        if language.is_empty() || !own_purpose_strings {
            continue;
        }
        let file = format!("{path}{relative}");
        let strings = read_plist(archive, &file).and_then(|plist| match plist.root {
            Value::Dictionary(dictionary) => Ok(dictionary),
            other => Err(format!(
                "a {}, not a dictionary of strings",
                other.type_name()
            )),
        });
        found.push(LocalizedInfo {
            path: file,
            bundle: format!("{path}{bundle}"),
            language: language.to_owned(),
            strings,
        });
    }
    found
}

fn read_plist<R: Read + Seek>(archive: &mut ZipArchive<R>, name: &str) -> Result<Plist, String> {
    let entry = archive.find(name).ok_or("not in the archive")?;
    if entry.uncompressed_size > MAX_PLIST_BYTES {
        return Err(format!("larger than {MAX_PLIST_BYTES} bytes"));
    }
    let index = entry.index;
    let bytes = archive
        .read(index)
        .map_err(|error: ArchiveError| error.to_string())?;
    plist::parse(&bytes).map_err(|error| error.to_string())
}

/// The main executable `CFBundleExecutable` names, when it is a plain file name the bundle
/// has.
fn main_executable(
    info: &BundleInfo,
    path: &str,
    has: &dyn Fn(&str) -> bool,
    problems: &mut Vec<IpaProblem>,
) -> Option<String> {
    let Some(name) = info.executable.as_deref() else {
        problems.push(IpaProblem::ExecutableNotDeclared);
        return None;
    };
    if !is_plain_file_name(name) {
        problems.push(IpaProblem::ExecutableNameInvalid(name.to_owned()));
        return None;
    }
    if !has(name) {
        problems.push(IpaProblem::ExecutableMissing(name.to_owned()));
        return None;
    }
    Some(format!("{path}{name}"))
}

/// Not empty, not `.` or `..`, no `/` or NUL: names one file in the bundle directory.
fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// Bundles and libraries in the places iOS loads them from, each with its `Info.plist`.
fn components<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    inside: &[&str],
    path: &str,
) -> Vec<BundleComponent> {
    const PLACES: [(&str, &str, ComponentKind); 5] = [
        ("Frameworks/", ".framework", ComponentKind::Framework),
        ("PlugIns/", ".appex", ComponentKind::AppExtension),
        (
            "Extensions/",
            ".appex",
            ComponentKind::ExtensionKitExtension,
        ),
        ("Watch/", ".app", ComponentKind::WatchApp),
        ("AppClips/", ".app", ComponentKind::AppClip),
    ];
    let mut found: BTreeSet<(ComponentKind, String)> = BTreeSet::new();
    for relative in inside {
        for (directory, suffix, kind) in PLACES {
            let Some(rest) = relative.strip_prefix(directory) else {
                continue;
            };
            if let Some((name, _)) = rest.split_once('/')
                && name.len() > suffix.len()
                && name.ends_with(suffix)
            {
                found.insert((kind, format!("{path}{directory}{name}/")));
            }
        }
        if let Some(library) = relative.strip_prefix("Frameworks/")
            && !library.contains('/')
            && library.ends_with(".dylib")
        {
            found.insert((ComponentKind::Library, format!("{path}{relative}")));
        }
    }
    found
        .into_iter()
        .map(|(kind, component)| read_component(archive, kind, component))
        .collect()
}

fn read_component<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    kind: ComponentKind,
    path: String,
) -> BundleComponent {
    if kind == ComponentKind::Library {
        return BundleComponent {
            kind,
            executable: Some(path.clone()),
            path,
            info: None,
            info_problem: None,
        };
    }
    let (info, info_problem) = match read_plist(archive, &format!("{path}Info.plist")) {
        Ok(plist) => match plist.root.as_dictionary() {
            Some(dictionary) => (Some(BundleInfo::of(dictionary)), None),
            None => (None, Some("Info.plist is not a dictionary".to_owned())),
        },
        Err(problem) => (None, Some(format!("Info.plist: {problem}"))),
    };
    let executable = info
        .as_ref()
        .and_then(|info| info.executable.as_deref())
        .filter(|name| is_plain_file_name(name))
        .map(|name| format!("{path}{name}"))
        .filter(|candidate| archive.find(candidate).is_some());
    BundleComponent {
        kind,
        path,
        info,
        info_problem,
        executable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn the_app_bundle_is_found_at_the_payload_root_first() {
        let mut problems = Vec::new();
        let located = locate_app_bundle(
            &names(&[
                "Payload/A.app/Info.plist",
                "Payload/A.app/Watch/W.app/Info.plist",
                "Payload/B.app/Info.plist",
            ]),
            &mut problems,
        );
        assert_eq!(located.as_deref(), Some("Payload/A.app/"));
        assert_eq!(
            problems,
            [IpaProblem::MultipleAppBundles(vec![
                "Payload/A.app/".into(),
                "Payload/B.app/".into()
            ])]
        );
        let mut problems = Vec::new();
        let located = locate_app_bundle(
            &names(&["Build/Payload/C.app/Info.plist", "D.app/x/y"]),
            &mut problems,
        );
        assert_eq!(located.as_deref(), Some("D.app/"));
        assert_eq!(
            problems,
            [IpaProblem::AppBundleNotAtPayloadRoot("D.app/".into())]
        );
        assert_eq!(
            locate_app_bundle(&names(&["Payload/.app/x", "x.app"]), &mut Vec::new()),
            None
        );
    }

    #[test]
    fn executable_names_are_plain_file_names() {
        for name in ["Fixture", "My App", "a.b"] {
            assert!(is_plain_file_name(name), "{name}");
        }
        for name in ["", ".", "..", "../x", "a/b", "a\0"] {
            assert!(!is_plain_file_name(name), "{name:?}");
        }
    }
}
