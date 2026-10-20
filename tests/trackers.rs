//! Trackers against MobSF's own tracker code (tests/fixtures/trackers, rebuilt by
//! build_trackers.py): the classes msec reads from the fixture's DEX file are the ones AOSP's
//! dexdump lists, and the trackers msec finds by code signature in them, and by network
//! signature in the hosts of the fixture IPA's URLs, are the ones MobSF v4.5.3's
//! `detect_trackers_in_list` finds with the same Exodus snapshot.

use std::collections::BTreeMap;
use std::path::Path;

use msec::android::Apk;
use msec::archive::{Limits, ZipArchive};
use msec::ios::Ipa;
use msec::trackers;
use msec::urls::{host_of, urls};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/trackers");

fn read(name: &str) -> String {
    std::fs::read_to_string(Path::new(DIR).join(name)).unwrap()
}

fn verdicts() -> BTreeMap<String, Vec<String>> {
    read("mobsf-verdicts.txt")
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('\t').unwrap();
            let items = value
                .split('|')
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect();
            (key.to_owned(), items)
        })
        .collect()
}

fn names(scan: &trackers::TrackerScan) -> Vec<String> {
    scan.trackers
        .iter()
        .map(|found| found.tracker.name.to_owned())
        .collect()
}

#[test]
fn apk_trackers_are_mobsfs() {
    let mut archive =
        ZipArchive::open_path(Path::new(DIR).join("trackers.apk"), Limits::default()).unwrap();
    let apk = Apk::read(&mut archive);
    let file = &apk.dex_files[0].container.files[0];
    let mut classes: Vec<&str> = file
        .classes
        .iter()
        .filter_map(|class| file.class_descriptor(class))
        .collect();
    classes.sort_unstable();
    let expected = read("classes.txt");
    assert_eq!(classes, expected.lines().collect::<Vec<_>>());
    let scan = trackers::scan_apk(&apk);
    assert_eq!(names(&scan), verdicts()["apk-code"]);
    assert_eq!(scan.classes_checked, 7);
    assert!(scan.trackers.iter().all(|found| found.network.is_none()));
    let adjust = scan
        .trackers
        .iter()
        .find(|found| found.tracker.name == "Adjust")
        .unwrap();
    let code = adjust.code.as_ref().unwrap();
    assert_eq!(code.class, "com.adjust.sdk.Adjust");
    assert_eq!((code.location.as_str(), code.classes), ("classes.dex", 1));
    assert_eq!(
        adjust.tracker.exodus_url(),
        format!(
            "https://reports.exodus-privacy.eu.org/trackers/{}/",
            adjust.tracker.id
        )
    );
}

#[test]
fn ipa_trackers_are_mobsfs() {
    let mut archive =
        ZipArchive::open_path(Path::new(DIR).join("trackers.ipa"), Limits::default()).unwrap();
    let ipa = Ipa::read(&mut archive);
    let verdicts = verdicts();
    // The hosts msec takes from endpoints.json are the ones Python's urlparse takes.
    let endpoints = String::from_utf8(
        archive
            .read_by_name("Payload/Fixture.app/endpoints.json")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let mut hosts: Vec<String> = urls(&endpoints).into_iter().filter_map(host_of).collect();
    hosts.sort();
    hosts.dedup();
    assert_eq!(hosts, verdicts["ipa-hosts"]);
    let scan = trackers::scan_ipa(&mut archive, &ipa);
    assert!(scan.complete());
    assert_eq!(names(&scan), verdicts["ipa-network"]);
    let mixpanel = scan
        .trackers
        .iter()
        .find(|found| found.tracker.name == "MixPanel")
        .unwrap();
    let network = mixpanel.network.as_ref().unwrap();
    assert_eq!(network.hosts, ["api.mixpanel.com"]);
    assert_eq!(network.location, "Payload/Fixture.app/endpoints.json");
    // The privacy manifest's tracking declarations are read.
    let manifest = ipa
        .app
        .as_ref()
        .unwrap()
        .privacy_manifests
        .iter()
        .find(|manifest| manifest.path == "Payload/Fixture.app/PrivacyInfo.xcprivacy")
        .unwrap();
    assert_eq!(manifest.tracking, Some(true));
    assert_eq!(manifest.tracking_domains, ["app.adjust.com"]);
}
