//! What an Android package contains, from its entry names alone: composition by category, DEX
//! files, native libraries per ABI, and the app frameworks and runtimes they reveal.
//!
//! Nothing here reads entry data, so it runs before (and independently of) the manifest and
//! code analyses. Sizes are the declared uncompressed sizes from the central directory.

use crate::archive::Entry;

/// What part of an Android package an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Category {
    /// `classes*.dex` at the root: the app's compiled code.
    Dex,
    /// `lib/<abi>/*.so`.
    NativeCode,
    /// `AndroidManifest.xml`.
    Manifest,
    /// `resources.arsc`.
    ResourceTable,
    /// `res/`.
    Resources,
    /// `assets/`.
    Assets,
    /// JAR signature files in `META-INF/` (v1 signing).
    Signatures,
    /// Other `META-INF/` files and Kotlin metadata.
    Metadata,
    /// Everything else.
    Other,
}

impl Category {
    /// Human-readable name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Dex => "DEX code",
            Self::NativeCode => "Native libraries",
            Self::Manifest => "Manifest",
            Self::ResourceTable => "Resource table",
            Self::Resources => "Resources",
            Self::Assets => "Assets",
            Self::Signatures => "Signature files",
            Self::Metadata => "Metadata",
            Self::Other => "Other",
        }
    }

    fn of(name: &str) -> Self {
        if is_root_dex(name) {
            Self::Dex
        } else if native_library(name).is_some() {
            Self::NativeCode
        } else if name == "AndroidManifest.xml" {
            Self::Manifest
        } else if name == "resources.arsc" {
            Self::ResourceTable
        } else if name.starts_with("res/") {
            Self::Resources
        } else if name.starts_with("assets/") {
            Self::Assets
        } else if is_signature_file(name) {
            Self::Signatures
        } else if name.starts_with("META-INF/") || name.starts_with("kotlin/") {
            Self::Metadata
        } else {
            Self::Other
        }
    }
}

/// Files and declared bytes in one category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryTotal {
    /// The category.
    pub category: Category,
    /// Number of files.
    pub files: usize,
    /// Sum of declared uncompressed sizes.
    pub uncompressed_bytes: u64,
}

/// An Android ABI directory under `lib/`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Abi {
    /// 64-bit ARM.
    Arm64V8a,
    /// 32-bit ARM (ARMv7).
    ArmeabiV7a,
    /// 32-bit ARMv5, removed in NDK r17.
    Armeabi,
    /// 64-bit x86.
    X86_64,
    /// 32-bit x86.
    X86,
    /// 64-bit RISC-V.
    Riscv64,
    /// 32-bit MIPS, removed in NDK r17.
    Mips,
    /// 64-bit MIPS, removed in NDK r17.
    Mips64,
    /// Any other directory name.
    Other(String),
}

impl Abi {
    fn from_directory(name: &str) -> Self {
        match name {
            "arm64-v8a" => Self::Arm64V8a,
            "armeabi-v7a" => Self::ArmeabiV7a,
            "armeabi" => Self::Armeabi,
            "x86_64" => Self::X86_64,
            "x86" => Self::X86,
            "riscv64" => Self::Riscv64,
            "mips" => Self::Mips,
            "mips64" => Self::Mips64,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The directory name, as Android uses it.
    pub fn name(&self) -> &str {
        match self {
            Self::Arm64V8a => "arm64-v8a",
            Self::ArmeabiV7a => "armeabi-v7a",
            Self::Armeabi => "armeabi",
            Self::X86_64 => "x86_64",
            Self::X86 => "x86",
            Self::Riscv64 => "riscv64",
            Self::Mips => "mips",
            Self::Mips64 => "mips64",
            Self::Other(name) => name,
        }
    }

    /// Which devices run code built for this ABI.
    pub fn devices(&self) -> &'static str {
        match self {
            Self::Arm64V8a => {
                "64-bit ARM phones, tablets, foldables and TVs (almost all current devices)"
            }
            Self::ArmeabiV7a => {
                "32-bit ARM devices, and 64-bit ARM devices that still run 32-bit apps"
            }
            Self::Armeabi => "ARMv5 devices (obsolete; unsupported since NDK r17)",
            Self::X86_64 => "x86 64-bit emulators and some Chromebooks",
            Self::X86 => "x86 32-bit emulators and older Intel devices",
            Self::Riscv64 => "RISC-V devices",
            Self::Mips | Self::Mips64 => "MIPS devices (obsolete; unsupported since NDK r17)",
            Self::Other(_) => "Not a standard Android ABI; Android ignores this directory",
        }
    }
}

/// Native libraries shipped for one ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbiLibraries {
    /// The ABI.
    pub abi: Abi,
    /// Library file names, sorted.
    pub libraries: Vec<String>,
    /// Sum of declared uncompressed sizes.
    pub uncompressed_bytes: u64,
}

/// What a framework is, for grouping in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameworkKind {
    /// Cross-platform app framework that draws its own UI or bridges to native views.
    CrossPlatform,
    /// Web content in a WebView, with native plugins.
    Hybrid,
    /// Game engine.
    GameEngine,
    /// JavaScript engine embedded by a framework.
    JavaScriptEngine,
    /// Native UI toolkit.
    UiToolkit,
    /// Programming language runtime.
    Language,
}

impl FrameworkKind {
    /// Human-readable name.
    pub fn label(self) -> &'static str {
        match self {
            Self::CrossPlatform => "Cross-platform",
            Self::Hybrid => "Hybrid (WebView)",
            Self::GameEngine => "Game engine",
            Self::JavaScriptEngine => "JavaScript engine",
            Self::UiToolkit => "UI toolkit",
            Self::Language => "Language",
        }
    }
}

/// An app framework or runtime recognisable from entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Framework {
    /// Flutter (Dart).
    Flutter,
    /// React Native.
    ReactNative,
    /// Expo (React Native tooling and runtime modules).
    Expo,
    /// Hermes JavaScript engine.
    Hermes,
    /// .NET for Android: .NET MAUI or Xamarin.
    DotNet,
    /// Unity.
    Unity,
    /// Unreal Engine.
    UnrealEngine,
    /// Godot.
    Godot,
    /// Cocos2d-x or Cocos Creator.
    Cocos,
    /// Apache Cordova (also used by Ionic).
    Cordova,
    /// Capacitor (Ionic).
    Capacitor,
    /// NativeScript.
    NativeScript,
    /// Qt.
    Qt,
    /// Jetpack Compose.
    JetpackCompose,
    /// Kotlin.
    Kotlin,
}

impl Framework {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Flutter => "Flutter",
            Self::ReactNative => "React Native",
            Self::Expo => "Expo",
            Self::Hermes => "Hermes",
            Self::DotNet => ".NET MAUI / Xamarin",
            Self::Unity => "Unity",
            Self::UnrealEngine => "Unreal Engine",
            Self::Godot => "Godot",
            Self::Cocos => "Cocos",
            Self::Cordova => "Cordova",
            Self::Capacitor => "Capacitor",
            Self::NativeScript => "NativeScript",
            Self::Qt => "Qt",
            Self::JetpackCompose => "Jetpack Compose",
            Self::Kotlin => "Kotlin",
        }
    }

    /// What kind of framework it is.
    pub fn kind(self) -> FrameworkKind {
        match self {
            Self::Flutter
            | Self::ReactNative
            | Self::Expo
            | Self::DotNet
            | Self::NativeScript
            | Self::Qt => FrameworkKind::CrossPlatform,
            Self::Cordova | Self::Capacitor => FrameworkKind::Hybrid,
            Self::Unity | Self::UnrealEngine | Self::Godot | Self::Cocos => {
                FrameworkKind::GameEngine
            }
            Self::Hermes => FrameworkKind::JavaScriptEngine,
            Self::JetpackCompose => FrameworkKind::UiToolkit,
            Self::Kotlin => FrameworkKind::Language,
        }
    }
}

/// How an entry name reveals a framework.
#[derive(Debug, Clone, Copy)]
enum Marker {
    /// Exact entry name.
    Exact(&'static str),
    /// Entry name prefix (a directory).
    Prefix(&'static str),
    /// Entry name suffix (an extension).
    Suffix(&'static str),
    /// File name of a native library under `lib/<abi>/`.
    Library(&'static str),
    /// File name prefix of a native library under `lib/<abi>/`.
    LibraryPrefix(&'static str),
}

impl Marker {
    fn matches(self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix),
            Self::Suffix(suffix) => name.ends_with(suffix),
            Self::Library(file) => native_library(name).is_some_and(|(_, library)| library == file),
            Self::LibraryPrefix(prefix) => {
                native_library(name).is_some_and(|(_, library)| library.starts_with(prefix))
            }
        }
    }
}

/// Markers per framework, in report order. Each marker is a file the framework's build tooling
/// puts in every release package by default.
const FRAMEWORK_MARKERS: &[(Framework, &[Marker])] = &[
    (
        Framework::Flutter,
        &[
            Marker::Library("libflutter.so"),
            Marker::Prefix("assets/flutter_assets/"),
        ],
    ),
    (
        Framework::ReactNative,
        &[
            Marker::Exact("assets/index.android.bundle"),
            Marker::Library("libreactnative.so"),
            Marker::Library("libreactnativejni.so"),
        ],
    ),
    (
        Framework::Expo,
        &[
            Marker::Exact("assets/app.config"),
            Marker::Exact("assets/app.manifest"),
        ],
    ),
    (
        Framework::Hermes,
        &[
            Marker::Library("libhermes.so"),
            Marker::Library("libhermesvm.so"),
        ],
    ),
    (
        Framework::DotNet,
        &[
            Marker::Library("libmonodroid.so"),
            Marker::Library("libmonosgen-2.0.so"),
            Marker::Prefix("assemblies/"),
        ],
    ),
    (
        Framework::Unity,
        &[
            Marker::Library("libunity.so"),
            Marker::Library("libil2cpp.so"),
            Marker::Prefix("assets/bin/Data/"),
        ],
    ),
    (
        Framework::UnrealEngine,
        &[
            Marker::Library("libUE4.so"),
            Marker::Library("libUnreal.so"),
        ],
    ),
    (Framework::Godot, &[Marker::Library("libgodot_android.so")]),
    (
        Framework::Cocos,
        &[
            Marker::Library("libcocos2dcpp.so"),
            Marker::Library("libcocos2djs.so"),
            Marker::Library("libcocos2dlua.so"),
            Marker::Library("libcocos.so"),
        ],
    ),
    (
        Framework::Cordova,
        &[Marker::Exact("assets/www/cordova.js")],
    ),
    (
        Framework::Capacitor,
        &[Marker::Exact("assets/capacitor.config.json")],
    ),
    (
        Framework::NativeScript,
        &[Marker::Library("libNativeScript.so")],
    ),
    (
        Framework::Qt,
        &[
            Marker::LibraryPrefix("libQt5Core"),
            Marker::LibraryPrefix("libQt6Core"),
        ],
    ),
    (
        Framework::JetpackCompose,
        &[
            Marker::Exact("META-INF/androidx.compose.runtime_runtime.version"),
            Marker::Exact("META-INF/androidx.compose.ui_ui.version"),
        ],
    ),
    (
        Framework::Kotlin,
        &[
            Marker::Suffix(".kotlin_builtins"),
            Marker::Suffix(".kotlin_module"),
        ],
    ),
];

/// At most this many entry names are kept as evidence per framework.
const MAX_EVIDENCE: usize = 3;

/// A framework found in the package, with the entries that show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkEvidence {
    /// The framework.
    pub framework: Framework,
    /// Up to three entry names that reveal it, most telling first.
    pub evidence: Vec<String>,
}

/// Contents of an Android package, from entry names and declared sizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Files (directory entries excluded).
    pub files: usize,
    /// Sum of declared uncompressed sizes.
    pub uncompressed_bytes: u64,
    /// Sum of compressed sizes.
    pub compressed_bytes: u64,
    /// Non-empty categories, in [`Category`] order.
    pub categories: Vec<CategoryTotal>,
    /// Root DEX files in load order (`classes.dex`, `classes2.dex`, ...).
    pub dex_files: Vec<String>,
    /// Native libraries per ABI, in [`Abi`] order.
    pub abis: Vec<AbiLibraries>,
    /// Frameworks found, in a fixed report order.
    pub frameworks: Vec<FrameworkEvidence>,
    /// v1 (JAR) signature files in `META-INF/`.
    pub signature_files: Vec<String>,
}

impl Inventory {
    /// Builds the inventory from archive entries.
    pub fn from_entries(entries: &[Entry]) -> Self {
        let files: Vec<&Entry> = entries.iter().filter(|entry| !entry.is_directory).collect();
        let mut inventory = Self {
            files: files.len(),
            uncompressed_bytes: files
                .iter()
                .map(|entry| entry.uncompressed_size)
                .fold(0, u64::saturating_add),
            compressed_bytes: files
                .iter()
                .map(|entry| entry.compressed_size)
                .fold(0, u64::saturating_add),
            categories: category_totals(&files),
            dex_files: dex_files(&files),
            abis: abi_libraries(&files),
            frameworks: frameworks(&files),
            signature_files: files
                .iter()
                .filter(|entry| is_signature_file(&entry.name))
                .map(|entry| entry.name.clone())
                .collect(),
        };
        inventory.signature_files.sort();
        inventory
    }

    /// True when the framework was found.
    pub fn has(&self, framework: Framework) -> bool {
        self.frameworks
            .iter()
            .any(|found| found.framework == framework)
    }
}

fn category_totals(files: &[&Entry]) -> Vec<CategoryTotal> {
    let mut totals: Vec<CategoryTotal> = Vec::new();
    for entry in files {
        let category = Category::of(&entry.name);
        match totals.iter_mut().find(|total| total.category == category) {
            Some(total) => {
                total.files += 1;
                total.uncompressed_bytes = total
                    .uncompressed_bytes
                    .saturating_add(entry.uncompressed_size);
            }
            None => totals.push(CategoryTotal {
                category,
                files: 1,
                uncompressed_bytes: entry.uncompressed_size,
            }),
        }
    }
    totals.sort_by_key(|total| total.category);
    totals
}

fn dex_files(files: &[&Entry]) -> Vec<String> {
    let mut names: Vec<String> = files
        .iter()
        .filter(|entry| is_root_dex(&entry.name))
        .map(|entry| entry.name.clone())
        .collect();
    // Android loads classes.dex, then classes2.dex, classes3.dex, ... in numeric order.
    names.sort_by_key(|name| (dex_number(name), name.clone()));
    names.dedup();
    names
}

fn abi_libraries(files: &[&Entry]) -> Vec<AbiLibraries> {
    let mut abis: Vec<AbiLibraries> = Vec::new();
    for entry in files {
        let Some((abi_directory, library)) = native_library(&entry.name) else {
            continue;
        };
        let abi = Abi::from_directory(abi_directory);
        let index = match abis.iter().position(|found| found.abi == abi) {
            Some(index) => index,
            None => {
                abis.push(AbiLibraries {
                    abi,
                    libraries: Vec::new(),
                    uncompressed_bytes: 0,
                });
                abis.len() - 1
            }
        };
        abis[index].libraries.push(library.to_owned());
        abis[index].uncompressed_bytes = abis[index]
            .uncompressed_bytes
            .saturating_add(entry.uncompressed_size);
    }
    for found in &mut abis {
        found.libraries.sort();
        found.libraries.dedup();
    }
    abis.sort_by(|left, right| left.abi.cmp(&right.abi));
    abis
}

fn frameworks(files: &[&Entry]) -> Vec<FrameworkEvidence> {
    FRAMEWORK_MARKERS
        .iter()
        .filter_map(|(framework, markers)| {
            // Marker order first (the most telling file leads), then central directory order.
            let evidence: Vec<String> = markers
                .iter()
                .flat_map(|marker| files.iter().filter(|entry| marker.matches(&entry.name)))
                .take(MAX_EVIDENCE)
                .map(|entry| entry.name.clone())
                .collect();
            (!evidence.is_empty()).then_some(FrameworkEvidence {
                framework: *framework,
                evidence,
            })
        })
        .collect()
}

fn is_root_dex(name: &str) -> bool {
    !name.contains('/') && name.starts_with("classes") && name.ends_with(".dex")
}

/// `classes.dex` is 1, `classes2.dex` is 2; anything else sorts last.
fn dex_number(name: &str) -> u32 {
    let digits = &name["classes".len()..name.len() - ".dex".len()];
    if digits.is_empty() {
        1
    } else {
        digits.parse().unwrap_or(u32::MAX)
    }
}

/// `(abi, file name)` for `lib/<abi>/<file>.so`. Android only loads libraries directly inside
/// the ABI directory.
fn native_library(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("lib/")?;
    let (abi, library) = rest.split_once('/')?;
    (!abi.is_empty() && !library.contains('/') && library.ends_with(".so"))
        .then_some((abi, library))
}

fn is_signature_file(name: &str) -> bool {
    let Some(file) = name.strip_prefix("META-INF/") else {
        return false;
    };
    if file.contains('/') {
        return false;
    }
    let upper = file.to_ascii_uppercase();
    upper == "MANIFEST.MF"
        || [".SF", ".RSA", ".DSA", ".EC"]
            .iter()
            .any(|extension| upper.ends_with(extension))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(names: &[(&str, u64)]) -> Vec<Entry> {
        names
            .iter()
            .enumerate()
            .map(|(index, (name, size))| Entry::for_test(index, name, *size))
            .collect()
    }

    #[test]
    fn categorises_a_typical_apk() {
        let inventory = Inventory::from_entries(&entries(&[
            ("AndroidManifest.xml", 4_000),
            ("classes.dex", 9_000_000),
            ("classes10.dex", 1_000),
            ("classes2.dex", 3_000_000),
            ("resources.arsc", 500_000),
            ("res/", 0),
            ("res/drawable/icon.png", 10_000),
            ("assets/data.bin", 7),
            ("lib/arm64-v8a/libapp.so", 2_000_000),
            ("lib/armeabi-v7a/libapp.so", 1_500_000),
            ("lib/arm64-v8a/nested/libignored.so", 1),
            ("META-INF/MANIFEST.MF", 100),
            ("META-INF/CERT.RSA", 1_000),
            ("META-INF/androidx.core_core.version", 10),
            ("kotlin/collections/collections.kotlin_builtins", 50),
            ("DebugProbesKt.bin", 700),
        ]));
        assert_eq!(inventory.files, 15);
        assert_eq!(
            inventory.dex_files,
            ["classes.dex", "classes2.dex", "classes10.dex"]
        );
        let abis: Vec<&str> = inventory
            .abis
            .iter()
            .map(|found| found.abi.name())
            .collect();
        assert_eq!(abis, ["arm64-v8a", "armeabi-v7a"]);
        assert_eq!(
            inventory.signature_files,
            ["META-INF/CERT.RSA", "META-INF/MANIFEST.MF"]
        );
        let categories: Vec<(Category, usize)> = inventory
            .categories
            .iter()
            .map(|total| (total.category, total.files))
            .collect();
        assert_eq!(
            categories,
            [
                (Category::Dex, 3),
                (Category::NativeCode, 2),
                (Category::Manifest, 1),
                (Category::ResourceTable, 1),
                (Category::Resources, 1),
                (Category::Assets, 1),
                (Category::Signatures, 2),
                (Category::Metadata, 2),
                (Category::Other, 2),
            ]
        );
        assert!(inventory.has(Framework::Kotlin));
        assert!(!inventory.has(Framework::Flutter));
    }

    #[test]
    fn recognises_cross_platform_frameworks() {
        let inventory = Inventory::from_entries(&entries(&[
            ("assets/flutter_assets/AssetManifest.json", 1),
            ("lib/arm64-v8a/libflutter.so", 1),
            ("lib/arm64-v8a/libapp.so", 1),
            ("assets/index.android.bundle", 1),
            ("lib/arm64-v8a/libhermes.so", 1),
            ("lib/arm64-v8a/libil2cpp.so", 1),
            ("lib/arm64-v8a/libQt6Core_arm64-v8a.so", 1),
            ("META-INF/androidx.compose.runtime_runtime.version", 1),
        ]));
        let found: Vec<Framework> = inventory
            .frameworks
            .iter()
            .map(|found| found.framework)
            .collect();
        assert_eq!(
            found,
            [
                Framework::Flutter,
                Framework::ReactNative,
                Framework::Hermes,
                Framework::Unity,
                Framework::Qt,
                Framework::JetpackCompose,
            ]
        );
        assert_eq!(
            inventory.frameworks[0].evidence,
            [
                "lib/arm64-v8a/libflutter.so",
                "assets/flutter_assets/AssetManifest.json"
            ]
        );
    }
}
