//! Components of APKs and app bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use super::{
    Component, ComponentInventory, ComponentKind, Confidence, DependencyEdge, Evidence,
    EvidenceSource,
};
use crate::android::proto::{Fields, ProtoProblem, WireValue};
use crate::android::signing::block::BlockKind;
use crate::android::{Apk, Bundle};
use crate::archive::ZipArchive;

/// Where the Android Gradle Plugin writes a bundle's dependency record.
const BUNDLE_DEPENDENCIES: &str =
    "BUNDLE-METADATA/com.android.tools.build.libraries/dependencies.pb";
/// Where it writes its own version, in a bundle and in an APK.
const BUNDLE_APP_METADATA: &str =
    "BUNDLE-METADATA/com.android.tools.build.gradle/app-metadata.properties";
const APK_APP_METADATA: &str = "META-INF/com/android/build/gradle/app-metadata.properties";
/// Small metadata files only; anything larger is not what the toolchain writes.
const MAX_METADATA_BYTES: u64 = 64 * 1024;
/// The dependency record of a large app is tens of kilobytes; this leaves room.
const MAX_DEPENDENCIES_BYTES: u64 = 16 * 1024 * 1024;
/// Play Core libraries whose `<client>.properties` carry no family prefix.
const PLAY_CORE_CLIENTS: [&str; 7] = [
    "core",
    "core-common",
    "app-update",
    "asset-delivery",
    "feature-delivery",
    "integrity",
    "review",
];

/// Components of an APK.
pub fn of_apk<R: Read + Seek>(archive: &mut ZipArchive<R>, apk: &Apk) -> ComponentInventory {
    let mut builder = Builder::default();
    metadata_files(archive, &mut builder, "");
    if let Some(version) = gradle_plugin_version(archive, APK_APP_METADATA) {
        builder
            .tools
            .push(("Android Gradle Plugin".to_owned(), version));
    }
    builder.native_libraries(
        apk.native_libraries
            .iter()
            .map(|library| library.path.as_str()),
    );
    let own_package = apk
        .manifest
        .as_ref()
        .and_then(|manifest| manifest.package.clone());
    builder.code_packages(&apk.dex_files, own_package.as_deref());
    let mut inventory = builder.finish();
    inventory.encrypted_dependency_info = apk
        .signing
        .other_blocks
        .contains(&BlockKind::DependencyInfo);
    inventory
}

/// Components of an app bundle: the Android Gradle Plugin's dependency record first, then the
/// metadata files each module ships under `root/`.
pub fn of_bundle<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    bundle: &Bundle,
) -> ComponentInventory {
    let mut builder = Builder::default();
    match read_small(archive, BUNDLE_DEPENDENCIES, MAX_DEPENDENCIES_BYTES) {
        Ok(Some(bytes)) => {
            if let Err(problem) = builder.bundle_dependencies(&bytes) {
                builder
                    .problems
                    .push(format!("{BUNDLE_DEPENDENCIES}: {problem:?}"));
            }
        }
        Ok(None) => {}
        Err(problem) => builder
            .problems
            .push(format!("{BUNDLE_DEPENDENCIES}: {problem}")),
    }
    for module in &bundle.modules {
        metadata_files(archive, &mut builder, &format!("{}/root/", module.name));
        builder.native_libraries(
            module
                .native_libraries
                .iter()
                .map(|library| library.path.as_str()),
        );
    }
    if let Some(version) = gradle_plugin_version(archive, BUNDLE_APP_METADATA) {
        builder
            .tools
            .push(("Android Gradle Plugin".to_owned(), version));
    }
    let own_package = bundle
        .modules
        .iter()
        .find(|module| module.name == "base")
        .and_then(|module| module.manifest.as_ref())
        .and_then(|manifest| manifest.package.clone());
    let dex_files: Vec<_> = bundle
        .modules
        .iter()
        .flat_map(|module| module.dex_files.iter().cloned())
        .collect();
    builder.code_packages(&dex_files, own_package.as_deref());
    builder.finish()
}

/// `META-INF/maven/**/pom.properties`, `META-INF/*.version` and root `*.properties` files
/// under `root` (`""` for an APK, `<module>/root/` in a bundle).
fn metadata_files<R: Read + Seek>(archive: &mut ZipArchive<R>, builder: &mut Builder, root: &str) {
    let entries: Vec<String> = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory && entry.name.starts_with(root))
        .map(|entry| entry.name.clone())
        .collect();
    for path in entries {
        let relative = &path[root.len()..];
        let kind =
            if relative.starts_with("META-INF/maven/") && relative.ends_with("/pom.properties") {
                EvidenceSource::PomProperties
            } else if relative.starts_with("META-INF/")
                && relative.ends_with(".version")
                && !relative["META-INF/".len()..].contains('/')
            {
                EvidenceSource::VersionFile
            } else if !relative.contains('/') && relative.ends_with(".properties") {
                EvidenceSource::ClientProperties
            } else {
                continue;
            };
        let text = match read_small(archive, &path, MAX_METADATA_BYTES) {
            Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
            Ok(None) => continue,
            Err(problem) => {
                builder.problems.push(format!("{path}: {problem}"));
                continue;
            }
        };
        match kind {
            EvidenceSource::PomProperties => builder.pom_properties(&path, &text),
            EvidenceSource::VersionFile => builder.version_file(&path, relative, &text),
            _ => builder.client_properties(&path, &text),
        }
    }
}

/// `androidGradlePluginVersion=` of an `app-metadata.properties`.
fn gradle_plugin_version<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    path: &str,
) -> Option<String> {
    let bytes = read_small(archive, path, MAX_METADATA_BYTES).ok()??;
    properties(&String::from_utf8_lossy(&bytes)).remove("androidGradlePluginVersion")
}

fn read_small<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    path: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>, String> {
    let Some(entry) = archive.find(path) else {
        return Ok(None);
    };
    if entry.uncompressed_size > limit {
        return Err(format!("larger than {limit} bytes"));
    }
    let index = entry.index;
    archive
        .read(index)
        .map(Some)
        .map_err(|error| error.to_string())
}

/// `key=value` lines (Java properties without escapes or continuations, as these files are
/// written).
fn properties(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(['#', '!']))
        .filter_map(|line| {
            let (key, value) = line.split_once(['=', ':'])?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// Collects components, merging what several files say about one.
#[derive(Default)]
struct Builder {
    /// By (kind, group, name).
    components: BTreeMap<(ComponentKind, Option<String>, String), Component>,
    /// Bundle library index to component key, for the dependency graph.
    bundle_keys: Vec<(ComponentKind, Option<String>, String)>,
    bundle_edges: Vec<(usize, Vec<usize>)>,
    code_packages: Vec<String>,
    tools: Vec<(String, String)>,
    problems: Vec<String>,
}

/// Evidence sources in the order their versions are trusted.
fn precedence(source: EvidenceSource) -> u8 {
    match source {
        EvidenceSource::BundleDependencies => 0,
        EvidenceSource::PomProperties => 1,
        EvidenceSource::VersionFile => 2,
        EvidenceSource::ClientProperties => 3,
        EvidenceSource::NativeLibrary | EvidenceSource::FrameworkInfo => 4,
    }
}

impl Builder {
    fn add(
        &mut self,
        kind: ComponentKind,
        group: Option<String>,
        name: String,
        version: Option<String>,
        confidence: Confidence,
        evidence: Evidence,
    ) -> (ComponentKind, Option<String>, String) {
        let key = (kind, group.clone(), name.clone());
        let source = evidence.source;
        let entry = self
            .components
            .entry(key.clone())
            .or_insert_with(|| Component {
                kind,
                group,
                name,
                version: None,
                confidence,
                evidence: Vec::new(),
                sha256: None,
                direct: None,
                packaging: None,
                bundle_identifier: None,
            });
        let trusted_more = entry
            .evidence
            .iter()
            .all(|seen| precedence(source) < precedence(seen.source));
        if version.is_some() && (entry.version.is_none() || trusted_more) {
            entry.version = version;
        }
        entry.confidence = entry.confidence.min(confidence);
        if !entry.evidence.contains(&evidence) {
            entry.evidence.push(evidence);
        }
        key
    }

    /// The bundle's `AppDependencies` message: libraries (field 1), their dependencies
    /// (field 2) and each module's direct dependencies (field 3).
    fn bundle_dependencies(&mut self, bytes: &[u8]) -> Result<(), ProtoProblem> {
        let mut direct: BTreeSet<usize> = BTreeSet::new();
        for field in Fields::new(bytes) {
            let (number, value) = field?;
            match number {
                1 => {
                    let key = self.bundle_library(value.bytes()?)?;
                    self.bundle_keys.push(key);
                }
                2 => {
                    // proto3 leaves out fields at their default: an absent library index is 0.
                    let mut library = 0;
                    let mut depends_on = Vec::new();
                    for field in Fields::new(value.bytes()?) {
                        match field? {
                            (1, value) => library = value.uint32()? as usize,
                            (2, value) => packed_indexes(value, &mut depends_on)?,
                            _ => {}
                        }
                    }
                    self.bundle_edges.push((library, depends_on));
                }
                3 => {
                    for field in Fields::new(value.bytes()?) {
                        if let (2, value) = field? {
                            let mut indexes = Vec::new();
                            packed_indexes(value, &mut indexes)?;
                            direct.extend(indexes);
                        }
                    }
                }
                _ => {}
            }
        }
        for (index, key) in self.bundle_keys.clone().into_iter().enumerate() {
            if let Some(component) = self.components.get_mut(&key) {
                component.direct = Some(direct.contains(&index));
            }
        }
        Ok(())
    }

    /// One `Library`: its `MavenLibrary` (field 1) and `Digests` (field 2, SHA-256 in field 1).
    fn bundle_library(
        &mut self,
        bytes: &[u8],
    ) -> Result<(ComponentKind, Option<String>, String), ProtoProblem> {
        let (mut group, mut artifact, mut packaging, mut classifier, mut version) = (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        );
        let mut sha256 = None;
        for field in Fields::new(bytes) {
            match field? {
                (1, value) => {
                    for field in Fields::new(value.bytes()?) {
                        match field? {
                            (1, value) => group = value.string()?.to_owned(),
                            (2, value) => artifact = value.string()?.to_owned(),
                            (3, value) => packaging = value.string()?.to_owned(),
                            (4, value) => classifier = value.string()?.to_owned(),
                            (5, value) => version = value.string()?.to_owned(),
                            _ => {}
                        }
                    }
                }
                (2, value) => {
                    for field in Fields::new(value.bytes()?) {
                        if let (1, value) = field? {
                            sha256 = Some(hex(value.bytes()?));
                        }
                    }
                }
                _ => {}
            }
        }
        let key = self.add(
            ComponentKind::Maven,
            (!group.is_empty()).then_some(group),
            artifact,
            (!version.is_empty()).then_some(version),
            Confidence::High,
            Evidence {
                source: EvidenceSource::BundleDependencies,
                path: BUNDLE_DEPENDENCIES.to_owned(),
            },
        );
        if let Some(component) = self.components.get_mut(&key) {
            component.sha256 = component.sha256.take().or(sha256);
            let shape = match (packaging.as_str(), classifier.as_str()) {
                ("" | "jar" | "aar", "") => None,
                (packaging, "") => Some(packaging.to_owned()),
                (packaging, classifier) => Some(format!("{packaging}:{classifier}")),
            };
            component.packaging = component.packaging.take().or(shape);
        }
        Ok(key)
    }

    fn pom_properties(&mut self, path: &str, text: &str) {
        let values = properties(text);
        let (Some(group), Some(artifact)) = (values.get("groupId"), values.get("artifactId"))
        else {
            return;
        };
        self.add(
            ComponentKind::Maven,
            Some(group.clone()),
            artifact.clone(),
            values.get("version").cloned(),
            Confidence::High,
            Evidence {
                source: EvidenceSource::PomProperties,
                path: path.to_owned(),
            },
        );
    }

    /// MobSF `android_sbom`: `<group>_<artifact>.version`, split at the one underscore when
    /// there is exactly one; otherwise the whole stem with underscores as dashes, in
    /// `org.jetbrains.kotlinx` when it starts with `kotlinx-`. A file naming a Gradle task
    /// instead of a version (`task ':…' property 'version'`) gives no version (MobSF:
    /// `dynamic`).
    fn version_file(&mut self, path: &str, relative: &str, text: &str) {
        let stem = relative
            .trim_start_matches("META-INF/")
            .trim_end_matches(".version");
        let parts: Vec<&str> = stem.split('_').collect();
        let (group, name) = if parts.len() == 2 {
            (Some(parts[0].to_owned()), parts[1].to_owned())
        } else {
            let name = stem.replace('_', "-");
            let group = name
                .starts_with("kotlinx-")
                .then(|| "org.jetbrains.kotlinx".to_owned());
            (group, name)
        };
        let content = text.trim();
        let version =
            (!content.is_empty() && !content.starts_with("task")).then(|| content.to_owned());
        let confidence = if version.is_some() {
            Confidence::High
        } else {
            Confidence::Low
        };
        self.add(
            ComponentKind::Maven,
            group,
            name,
            version,
            confidence,
            Evidence {
                source: EvidenceSource::VersionFile,
                path: path.to_owned(),
            },
        );
    }

    /// `<client>.properties` of Google Play services, Firebase and Play Core: `version=` and
    /// `client=` (the artifact); the group follows the client's family.
    fn client_properties(&mut self, path: &str, text: &str) {
        let values = properties(text);
        let (Some(client), Some(version)) = (values.get("client"), values.get("version")) else {
            return;
        };
        let (group, confidence) = if client.starts_with("firebase-") {
            (Some("com.google.firebase"), Confidence::High)
        } else if client.starts_with("play-services-") {
            (Some("com.google.android.gms"), Confidence::High)
        } else if PLAY_CORE_CLIENTS.contains(&client.as_str()) {
            (Some("com.google.android.play"), Confidence::Medium)
        } else {
            (None, Confidence::Medium)
        };
        self.add(
            ComponentKind::Maven,
            group.map(str::to_owned),
            client.clone(),
            Some(version.clone()),
            confidence,
            Evidence {
                source: EvidenceSource::ClientProperties,
                path: path.to_owned(),
            },
        );
    }

    /// One component per library file name, with every ABI's copy as evidence.
    fn native_libraries<'a>(&mut self, paths: impl Iterator<Item = &'a str>) {
        for path in paths {
            let name = path.rsplit('/').next().unwrap_or(path).to_owned();
            self.add(
                ComponentKind::NativeLibrary,
                None,
                name,
                None,
                Confidence::Low,
                Evidence {
                    source: EvidenceSource::NativeLibrary,
                    path: path.to_owned(),
                },
            );
        }
    }

    /// MobSF `extract_packages` on the DEX classes: every class's package, merged into a
    /// shorter package that has classes too, without the app's own package and names whose
    /// every part has one or two characters (obfuscated).
    fn code_packages(&mut self, dex_files: &[crate::android::dex::DexEntry], own: Option<&str>) {
        let mut packages: BTreeSet<String> = BTreeSet::new();
        for entry in dex_files {
            for file in &entry.container.files {
                for class in &file.classes {
                    let Some(descriptor) = file.class_descriptor(class) else {
                        continue;
                    };
                    let name = descriptor
                        .strip_prefix('L')
                        .and_then(|name| name.strip_suffix(';'))
                        .unwrap_or(descriptor);
                    let Some((package, _)) = name.rsplit_once('/') else {
                        continue;
                    };
                    let package = package.replace('/', ".");
                    let obfuscated = package.split('.').all(|part| part.chars().count() <= 2);
                    let own_code = own.is_some_and(|own| {
                        package == own || package.starts_with(&format!("{own}."))
                    });
                    if !obfuscated && !own_code {
                        packages.insert(package);
                    }
                }
            }
        }
        let mut merged: Vec<String> = Vec::new();
        for package in packages {
            if merged
                .last()
                .is_none_or(|last| !package.starts_with(&format!("{last}.")))
            {
                merged.push(package);
            }
        }
        self.code_packages = merged;
    }

    fn finish(self) -> ComponentInventory {
        let keys: Vec<_> = self.components.keys().cloned().collect();
        let position =
            |key: &(ComponentKind, Option<String>, String)| keys.iter().position(|k| k == key);
        let dependencies = self
            .bundle_edges
            .iter()
            .filter_map(|(library, depends_on)| {
                let component = position(self.bundle_keys.get(*library)?)?;
                let mut targets: Vec<usize> = depends_on
                    .iter()
                    .filter_map(|index| position(self.bundle_keys.get(*index)?))
                    .collect();
                targets.sort_unstable();
                targets.dedup();
                Some(DependencyEdge {
                    component,
                    depends_on: targets,
                })
            })
            .collect();
        ComponentInventory {
            components: self.components.into_values().collect(),
            dependencies,
            code_packages: self.code_packages,
            build_tools: self.tools,
            encrypted_dependency_info: false,
            problems: self.problems,
        }
    }
}

/// A repeated `int32` field, packed (one length-delimited run of varints) or not.
fn packed_indexes(value: WireValue<'_>, into: &mut Vec<usize>) -> Result<(), ProtoProblem> {
    match value {
        WireValue::Varint(index) => {
            into.push(index as u32 as usize);
            Ok(())
        }
        WireValue::Bytes(bytes) => {
            let mut position = 0;
            while position < bytes.len() {
                let mut index: u64 = 0;
                let mut shift = 0;
                loop {
                    let byte = *bytes.get(position).ok_or(ProtoProblem::BadVarint)?;
                    position += 1;
                    if shift < 64 {
                        index |= u64::from(byte & 0x7f) << shift;
                    }
                    shift += 7;
                    if byte & 0x80 == 0 {
                        break;
                    }
                    if shift >= 70 {
                        return Err(ProtoProblem::BadVarint);
                    }
                }
                into.push(index as u32 as usize);
            }
            Ok(())
        }
        _ => Err(ProtoProblem::WrongWireType),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_files_read_as_mobsf_reads_them() {
        let mut builder = Builder::default();
        builder.version_file(
            "META-INF/androidx.core_core.version",
            "META-INF/androidx.core_core.version",
            "1.15.0\n",
        );
        builder.version_file(
            "META-INF/kotlinx_coroutines_core.version",
            "META-INF/kotlinx_coroutines_core.version",
            "1.10.1",
        );
        builder.version_file(
            "META-INF/androidx.arch.core_core-runtime.version",
            "META-INF/androidx.arch.core_core-runtime.version",
            "task ':arch:core:core-runtime:writeVersionFile' property 'version'",
        );
        let inventory = builder.finish();
        let found: Vec<(Option<&str>, &str, Option<&str>, Confidence)> = inventory
            .components
            .iter()
            .map(|component| {
                (
                    component.group.as_deref(),
                    component.name.as_str(),
                    component.version.as_deref(),
                    component.confidence,
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                (
                    Some("androidx.arch.core"),
                    "core-runtime",
                    None,
                    Confidence::Low
                ),
                (
                    Some("androidx.core"),
                    "core",
                    Some("1.15.0"),
                    Confidence::High
                ),
                (
                    Some("org.jetbrains.kotlinx"),
                    "kotlinx-coroutines-core",
                    Some("1.10.1"),
                    Confidence::High
                ),
            ]
        );
    }

    #[test]
    fn client_properties_name_the_family() {
        let mut builder = Builder::default();
        builder.client_properties(
            "firebase-auth-interop.properties",
            "version=20.0.0\nclient=firebase-auth-interop\n",
        );
        builder.client_properties(
            "core-common.properties",
            "version=2.0.3\nclient=core-common\n",
        );
        let inventory = builder.finish();
        let purls: Vec<Option<String>> = inventory
            .components
            .iter()
            .map(|component| component.purl())
            .collect();
        assert_eq!(
            purls,
            [
                Some("pkg:maven/com.google.android.play/core-common@2.0.3".to_owned()),
                Some("pkg:maven/com.google.firebase/firebase-auth-interop@20.0.0".to_owned()),
            ]
        );
    }
}
