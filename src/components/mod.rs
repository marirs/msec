//! The third-party components an app package carries, with the evidence for each and how far
//! it identifies a version: the inventory a software bill of materials (SBOM) is built from.
//!
//! Ports MobSF's `android/sbom_analysis.py` (`META-INF/*.version` files and the Java packages of
//! the code) and adds, as msec origin, the sources that name exact versions:
//!
//! | Package | Source | Identifies | Confidence |
//! |---|---|---|---|
//! | AAB | `BUNDLE-METADATA/com.android.tools.build.libraries/dependencies.pb`: the Android Gradle Plugin's record of every resolved library (`AppDependencies`, field numbers read from AGP 9.4.1's generated classes) | Maven coordinates, version, SHA-256, dependency graph, direct dependencies | high |
//! | APK, AAB | `META-INF/maven/<group>/<artifact>/pom.properties` | Maven coordinates and version | high |
//! | APK, AAB | `META-INF/<group>_<artifact>.version` (AndroidX, Kotlin libraries), read as MobSF reads them | Maven coordinates; a version unless the file names a build task | high, or low without a version |
//! | APK, AAB | `<client>.properties` at the package root (Google Play services, Firebase, Play Core): `version=` and `client=` | artifact and version; the group from the client's family | high, medium when the group is inferred |
//! | APK, AAB | native libraries (`lib/<abi>/*.so`) | a file name, no version | low |
//! | IPA | frameworks and libraries in `Frameworks/`, with their `Info.plist` | name, bundle identifier, version | medium (vendors leave version keys wrong) |
//!
//! The Java packages of the code (MobSF's `sbom_packages`) are kept apart as
//! [`ComponentInventory::code_packages`]: they name code, not versions. An APK's own record of its
//! dependencies, which the Android Gradle Plugin writes into the APK Signing Block, is encrypted
//! with Google Play's key; msec notes that it is there ([`ComponentInventory::encrypted_dependency_info`])
//! and cannot read it.

mod android;
mod ios;

pub use android::{of_apk, of_bundle};
pub use ios::of_ipa;

/// How far a component's identity and version are established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Named by build metadata the toolchain writes (Gradle's resolution, Maven's properties).
    High,
    /// Named by metadata a vendor writes and may leave wrong, or with an inferred part.
    Medium,
    /// Only a name, without a version.
    Low,
}

impl Confidence {
    /// `high`, `medium`, `low`.
    pub fn key(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// What a component is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComponentKind {
    /// A Maven library (Android): `group:artifact`.
    Maven,
    /// A native library file (Android).
    NativeLibrary,
    /// An iOS framework or dynamic library.
    Framework,
}

/// Where a component was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceSource {
    /// The bundle's `dependencies.pb`.
    BundleDependencies,
    /// `META-INF/maven/.../pom.properties`.
    PomProperties,
    /// `META-INF/<group>_<artifact>.version`.
    VersionFile,
    /// `<client>.properties` (Google Play services and Firebase).
    ClientProperties,
    /// A native library file.
    NativeLibrary,
    /// A framework's `Info.plist`.
    FrameworkInfo,
}

impl EvidenceSource {
    /// `bundle_dependencies`, `pom_properties`, ...
    pub fn key(self) -> &'static str {
        match self {
            Self::BundleDependencies => "bundle_dependencies",
            Self::PomProperties => "pom_properties",
            Self::VersionFile => "version_file",
            Self::ClientProperties => "client_properties",
            Self::NativeLibrary => "native_library",
            Self::FrameworkInfo => "framework_info",
        }
    }
}

/// One piece of evidence: the source and the file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Evidence {
    /// What kind of evidence.
    pub source: EvidenceSource,
    /// The file in the package.
    pub path: String,
}

/// A third-party component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// What it is.
    pub kind: ComponentKind,
    /// Maven group (`androidx.core`); `None` when unknown or not Maven.
    pub group: Option<String>,
    /// Maven artifact (`core-ktx`), library file name (`libsqlcipher.so`) or framework name
    /// (`Alamofire`).
    pub name: String,
    /// The version, when the evidence names one.
    pub version: Option<String>,
    /// How far identity and version are established.
    pub confidence: Confidence,
    /// Every place it was seen.
    pub evidence: Vec<Evidence>,
    /// SHA-256 (hexadecimal) of the library's files, when the build recorded it.
    pub sha256: Option<String>,
    /// A module declares it directly (bundle metadata); `None` when unknown.
    pub direct: Option<bool>,
    /// Maven packaging and classifier, when not the default `jar`/`aar` without a classifier.
    pub packaging: Option<String>,
    /// iOS: the framework's bundle identifier.
    pub bundle_identifier: Option<String>,
}

impl Component {
    /// The package URL (`pkg:maven/androidx.core/core@1.15.0`), for Maven components with a
    /// group; `None` otherwise (native libraries and frameworks have no registry this
    /// evidence names).
    pub fn purl(&self) -> Option<String> {
        if self.kind != ComponentKind::Maven {
            return None;
        }
        let group = self.group.as_deref()?;
        let base = format!("pkg:maven/{}/{}", purl_part(group), purl_part(&self.name));
        Some(match &self.version {
            Some(version) => format!("{base}@{}", purl_part(version)),
            None => base,
        })
    }

    /// `group:name` (Maven) or the name.
    pub fn coordinates(&self) -> String {
        match &self.group {
            Some(group) => format!("{group}:{}", self.name),
            None => self.name.clone(),
        }
    }
}

/// Percent-encodes what a purl segment may not hold literally (purl spec: unreserved
/// characters and `.`, `-`, `_`, `~` stay).
fn purl_part(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// A component's direct dependencies (indexes into [`ComponentInventory::components`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEdge {
    /// The component.
    pub component: usize,
    /// What it depends on.
    pub depends_on: Vec<usize>,
}

/// The components of a package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentInventory {
    /// Components, Maven first (by coordinates), then native libraries, then frameworks.
    pub components: Vec<Component>,
    /// The dependency graph, when the bundle metadata records it.
    pub dependencies: Vec<DependencyEdge>,
    /// Java packages of the code (MobSF's `sbom_packages`): every package of a class, merged
    /// into its parent when the parent has classes too, without the app's own package and
    /// obfuscated names.
    pub code_packages: Vec<String>,
    /// The build toolchain: `(name, version)`, such as `("Android Gradle Plugin", "8.12.2")`.
    pub build_tools: Vec<(String, String)>,
    /// The APK Signing Block holds the Android Gradle Plugin's dependency record, encrypted for
    /// Google Play (unreadable).
    pub encrypted_dependency_info: bool,
    /// Metadata that could not be read, and why.
    pub problems: Vec<String>,
}

impl ComponentInventory {
    /// Components with a version.
    pub fn versioned(&self) -> impl Iterator<Item = &Component> {
        self.components
            .iter()
            .filter(|component| component.version.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purls_follow_the_spec() {
        let component = Component {
            kind: ComponentKind::Maven,
            group: Some("androidx.core".to_owned()),
            name: "core-ktx".to_owned(),
            version: Some("1.15.0".to_owned()),
            confidence: Confidence::High,
            evidence: Vec::new(),
            sha256: None,
            direct: None,
            packaging: None,
            bundle_identifier: None,
        };
        assert_eq!(
            component.purl().as_deref(),
            Some("pkg:maven/androidx.core/core-ktx@1.15.0")
        );
        assert_eq!(purl_part("1.0+build 7"), "1.0%2Bbuild%207");
        assert_eq!(component.coordinates(), "androidx.core:core-ktx");
    }
}
