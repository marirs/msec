//! Component inventory against independent writers (tests/fixtures/components, rebuilt by
//! build_components.py): a bundle dependency record written and read back by the Android Gradle
//! Plugin's own generated protobuf classes (expected-bundle.txt), and metadata files whose
//! expected components are written down where the files are made (expected-files.txt).

use std::path::Path;

use msec::android::{Apk, Bundle};
use msec::archive::{Limits, ZipArchive};
use msec::components::{
    self, Component, ComponentInventory, ComponentKind, Confidence, EvidenceSource,
};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/components");

fn read(name: &str) -> String {
    std::fs::read_to_string(Path::new(DIR).join(name)).unwrap()
}

fn find<'a>(inventory: &'a ComponentInventory, coordinates: &str) -> &'a Component {
    inventory
        .components
        .iter()
        .find(|component| component.coordinates() == coordinates)
        .unwrap_or_else(|| panic!("{coordinates} missing"))
}

/// `group:name@version` (`@-` without a version).
fn label(component: &Component) -> String {
    format!(
        "{}@{}",
        component.coordinates(),
        component.version.as_deref().unwrap_or("-")
    )
}

fn assert_files(inventory: &ComponentInventory, root: &str) {
    for line in read("expected-files.txt").lines() {
        let (path, expected) = line.split_once('\t').unwrap();
        let coordinates = expected.rsplit_once('@').unwrap().0;
        let component = find(inventory, coordinates);
        assert_eq!(label(component), expected, "{path}");
        assert!(
            component
                .evidence
                .iter()
                .any(|evidence| evidence.path == format!("{root}{path}")),
            "{path}: {:?}",
            component.evidence
        );
    }
}

#[test]
fn bundle_record_reads_as_agp_reads_it() {
    let mut archive =
        ZipArchive::open_path(Path::new(DIR).join("components.aab"), Limits::default()).unwrap();
    let bundle = Bundle::read(&mut archive);
    let inventory = components::of_bundle(&mut archive, &bundle);
    assert_eq!(inventory.problems, Vec::<String>::new());
    let expected = read("expected-bundle.txt");
    let mut names_by_index = Vec::new();
    for line in expected
        .lines()
        .filter(|line| line.starts_with("library\t"))
    {
        let fields: Vec<&str> = line.split('\t').collect();
        let (group, artifact, packaging, classifier, version, sha256, direct) = (
            fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8],
        );
        let coordinates = format!("{group}:{artifact}");
        let component = find(&inventory, &coordinates);
        assert_eq!(component.kind, ComponentKind::Maven);
        assert_eq!(component.version.as_deref(), Some(version), "{coordinates}");
        assert_eq!(component.sha256.as_deref(), Some(sha256), "{coordinates}");
        assert_eq!(component.direct, Some(direct == "true"), "{coordinates}");
        assert_eq!(component.confidence, Confidence::High);
        let shape = match (packaging, classifier) {
            ("jar" | "aar", "") => None,
            (packaging, "") => Some(packaging.to_owned()),
            (packaging, classifier) => Some(format!("{packaging}:{classifier}")),
        };
        assert_eq!(component.packaging, shape, "{coordinates}");
        assert!(
            component
                .evidence
                .iter()
                .any(|evidence| evidence.source == EvidenceSource::BundleDependencies)
        );
        names_by_index.push(coordinates);
    }
    assert_eq!(names_by_index.len(), 6);
    // The dependency graph, by coordinates.
    let mut edges: Vec<(String, Vec<String>)> = inventory
        .dependencies
        .iter()
        .map(|edge| {
            (
                inventory.components[edge.component].coordinates(),
                edge.depends_on
                    .iter()
                    .map(|index| inventory.components[*index].coordinates())
                    .collect(),
            )
        })
        .collect();
    edges.sort();
    let mut expected_edges: Vec<(String, Vec<String>)> = expected
        .lines()
        .filter(|line| line.starts_with("edge\t"))
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            let from = names_by_index[fields[1].parse::<usize>().unwrap()].clone();
            let mut to: Vec<String> = fields[2]
                .split(',')
                .map(|index| names_by_index[index.parse::<usize>().unwrap()].clone())
                .collect();
            to.sort();
            (from, to)
        })
        .collect();
    expected_edges.sort();
    assert_eq!(edges, expected_edges);
    // The metadata files under base/root/ describe the same and more components.
    assert_files(&inventory, "base/root/");
    let core = find(&inventory, "androidx.core:core");
    assert_eq!(core.evidence.len(), 2, "{:?}", core.evidence);
    assert_eq!(
        inventory.build_tools,
        [("Android Gradle Plugin".to_owned(), "9.4.1".to_owned())]
    );
    assert_eq!(
        find(&inventory, "androidx.core:core").purl().as_deref(),
        Some("pkg:maven/androidx.core/core@1.15.0")
    );
}

#[test]
fn apk_metadata_files_libraries_and_packages() {
    let mut archive =
        ZipArchive::open_path(Path::new(DIR).join("components.apk"), Limits::default()).unwrap();
    let apk = Apk::read(&mut archive);
    let inventory = components::of_apk(&mut archive, &apk);
    assert_files(&inventory, "");
    assert_eq!(
        find(&inventory, "androidx.arch.core:core-runtime").confidence,
        Confidence::Low
    );
    let library = find(&inventory, "libsqlcipher.so");
    assert_eq!(
        (library.kind, library.version.as_deref(), library.confidence),
        (ComponentKind::NativeLibrary, None, Confidence::Low)
    );
    assert_eq!(
        inventory.build_tools,
        [("Android Gradle Plugin".to_owned(), "9.4.1".to_owned())]
    );
    assert!(!inventory.encrypted_dependency_info);
    // The fixture's own code is its package; nothing else is in its DEX files.
    assert_eq!(inventory.code_packages, Vec::<String>::new());
}

/// IPA: the frameworks and libraries in Frameworks/, versioned by their Info.plist as
/// tests/fixtures/ios/make_ipa.py writes it (`framework_info`: version 1.0, identifier
/// dev.appchk.fixture.Lib); a loose library has no Info.plist, so no version.
#[test]
fn ipa_frameworks_and_libraries() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ios/ipa/fixture.ipa"
    );
    let mut archive = ZipArchive::open_path(path, Limits::default()).unwrap();
    let ipa = msec::ios::Ipa::read(&mut archive);
    let inventory = components::of_ipa(&ipa);
    let found: Vec<(&str, Option<&str>, Option<&str>, Confidence)> = inventory
        .components
        .iter()
        .map(|component| {
            (
                component.name.as_str(),
                component.version.as_deref(),
                component.bundle_identifier.as_deref(),
                component.confidence,
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (
                "Lib",
                Some("1.0"),
                Some("dev.appchk.fixture.Lib"),
                Confidence::Medium
            ),
            ("libextra", None, None, Confidence::Low),
        ]
    );
    assert!(
        inventory
            .components
            .iter()
            .all(|component| component.purl().is_none())
    );
}
