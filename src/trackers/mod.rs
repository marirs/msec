//! Third-party trackers, recognised with the εxodus tracker database as MobSF recognises them
//! (`MalwareAnalyzer/views/Trackers.py`): a tracker's code signature (Java package prefixes,
//! matched with `re.search` against every class descriptor of the DEX files, as baksmali lists
//! them) or its network signature (domain patterns, matched against the hosts of the URLs the
//! package holds). Only signatures longer than three characters are used, as in MobSF.
//!
//! The database is a snapshot shipped with msec (`generated/exodus.rs`, ODbL 1.0); MobSF
//! refreshes it from the Exodus API on every scan when online. msec never goes online during a
//! scan.
//!
//! APKs and app bundles are checked by code signature only, as in MobSF: matching network
//! signatures against the URLs an APK's strings hold flags trackers from documentation links in
//! SDK error messages (`developers.google.com` matches Google Ads). IPAs are checked by network
//! signature only, as in MobSF (Exodus' code signatures are Java packages), so an IPA's
//! trackers are leads: a domain in a string is not proof the app contacts it.
//!
//! Departs from MobSF on purpose (PORTING.md deviation 37): network signatures are matched
//! against each URL's full host rather than its registrable domain (MobSF reduces hosts with
//! `tldextract`, which needs the Public Suffix List), so a signature written with a leading dot
//! (`\.crashlytics\.com`) matches `settings.crashlytics.com`.

pub(crate) mod generated;

use std::collections::BTreeMap;
use std::io::{Read, Seek};
use std::sync::LazyLock;

use regex::{RegexSet, RegexSetBuilder};

use crate::android::dex::DexEntry;
use crate::android::{Apk, Bundle};
use crate::archive::ZipArchive;
use crate::ios::Ipa;
use crate::package_strings::android::class_name;
use crate::package_strings::ios::walk_ipa;
use crate::package_strings::{PackageString, Unread, Visitor};
use crate::urls::{host_of, urls};

/// Hosts listed per network match.
const HOSTS_LISTED: usize = 5;

/// One tracker of the εxodus database.
#[derive(Debug)]
pub struct ExodusTracker {
    /// Exodus ID (`https://reports.exodus-privacy.eu.org/trackers/<id>`).
    pub id: u32,
    /// Name.
    pub name: &'static str,
    /// The tracker's website.
    pub website: &'static str,
    /// Exodus categories (`Analytics`, `Advertisement`, ...).
    pub categories: &'static [&'static str],
    /// Package prefixes, as a regular expression.
    pub code_signature: &'static str,
    /// Domains, as a regular expression.
    pub network_signature: &'static str,
    /// When Exodus added it.
    pub creation_date: &'static str,
}

impl ExodusTracker {
    /// The tracker's page on the Exodus site.
    pub fn exodus_url(&self) -> String {
        format!(
            "https://reports.exodus-privacy.eu.org/trackers/{}/",
            self.id
        )
    }
}

/// The class that matched a tracker's code signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMatch {
    /// The first matching class, dotted (`com.facebook.appevents.AppEventsLogger`).
    pub class: String,
    /// The DEX file it is in.
    pub location: String,
    /// How many classes match.
    pub classes: usize,
}

/// The hosts that matched a tracker's network signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMatch {
    /// The matching hosts, the first five in the order found.
    pub hosts: Vec<String>,
    /// Where the first one was found.
    pub location: String,
}

/// A tracker found in the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTracker {
    /// The tracker.
    pub tracker: &'static ExodusTracker,
    /// Found by its code signature.
    pub code: Option<CodeMatch>,
    /// Found by its network signature.
    pub network: Option<NetworkMatch>,
}

impl PartialEq for ExodusTracker {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ExodusTracker {}

/// Trackers found in a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerScan {
    /// Trackers found, by name (as MobSF sorts them).
    pub trackers: Vec<DetectedTracker>,
    /// Trackers in the database.
    pub signatures: usize,
    /// When the database snapshot was retrieved.
    pub database_retrieved: &'static str,
    /// Class descriptors checked.
    pub classes_checked: usize,
    /// Distinct hosts checked.
    pub hosts_checked: usize,
    /// Files whose text was not read (hosts in them were not checked).
    pub skipped: Vec<Unread>,
}

impl TrackerScan {
    /// Every file that should have been read was read.
    pub fn complete(&self) -> bool {
        self.skipped.is_empty()
    }
}

/// Every tracker in the database.
pub fn database() -> &'static [ExodusTracker] {
    generated::exodus::TRACKERS
}

struct Signatures {
    /// Code signatures longer than three characters, and the tracker each belongs to.
    code: RegexSet,
    code_owners: Vec<usize>,
    network: RegexSet,
    network_owners: Vec<usize>,
}

static SIGNATURES: LazyLock<Signatures> = LazyLock::new(|| {
    let build = |pick: fn(&ExodusTracker) -> &'static str| {
        let (owners, patterns): (Vec<usize>, Vec<&str>) = database()
            .iter()
            .enumerate()
            .map(|(index, tracker)| (index, pick(tracker)))
            .filter(|(_, pattern)| pattern.chars().count() > 3)
            .unzip();
        let set = RegexSetBuilder::new(patterns)
            .size_limit(1 << 28)
            .dfa_size_limit(1 << 28)
            .build()
            .expect("every Exodus signature compiles");
        (set, owners)
    };
    let (code, code_owners) = build(|tracker| tracker.code_signature);
    let (network, network_owners) = build(|tracker| tracker.network_signature);
    Signatures {
        code,
        code_owners,
        network,
        network_owners,
    }
});

/// Collects the hosts of every URL in a package's strings, each with where it was first seen.
#[derive(Default)]
struct Hosts {
    first_seen: BTreeMap<String, (usize, String)>,
    skipped: Vec<Unread>,
}

impl Hosts {
    fn add(&mut self, text: &str, location: &str) {
        for url in urls(text) {
            if let Some(host) = host_of(url) {
                let order = self.first_seen.len();
                self.first_seen
                    .entry(host)
                    .or_insert_with(|| (order, location.to_owned()));
            }
        }
    }
}

impl Visitor for Hosts {
    fn string(&mut self, string: &PackageString<'_>) {
        self.add(string.text, string.location);
    }

    fn text_file(&mut self, location: &str, text: &str) {
        self.add(text, location);
    }

    fn skipped(&mut self, path: &str, reason: &str) {
        self.skipped.push(Unread {
            path: path.to_owned(),
            reason: reason.to_owned(),
        });
    }
}

/// Trackers in an APK, by code signature on its DEX classes.
pub fn scan_apk(apk: &Apk) -> TrackerScan {
    detect(&apk.dex_files, Hosts::default())
}

/// Trackers in an app bundle, by code signature on every module's DEX classes.
pub fn scan_bundle(bundle: &Bundle) -> TrackerScan {
    let dex_files: Vec<DexEntry> = bundle
        .modules
        .iter()
        .flat_map(|module| module.dex_files.iter().cloned())
        .collect();
    detect(&dex_files, Hosts::default())
}

/// Trackers in an IPA, by network signature (Exodus' code signatures are Java packages).
pub fn scan_ipa<R: Read + Seek>(archive: &mut ZipArchive<R>, ipa: &Ipa) -> TrackerScan {
    let mut hosts = Hosts::default();
    walk_ipa(archive, ipa, &mut hosts);
    detect(&[], hosts)
}

fn detect(dex_files: &[DexEntry], hosts: Hosts) -> TrackerScan {
    let signatures = &*SIGNATURES;
    let mut code: BTreeMap<usize, CodeMatch> = BTreeMap::new();
    let mut classes_checked = 0;
    for entry in dex_files {
        for file in &entry.container.files {
            for class in &file.classes {
                let Some(descriptor) = file.class_descriptor(class) else {
                    continue;
                };
                classes_checked += 1;
                for matched in signatures.code.matches(descriptor).iter() {
                    let tracker = signatures.code_owners[matched];
                    code.entry(tracker)
                        .and_modify(|found| found.classes += 1)
                        .or_insert_with(|| CodeMatch {
                            class: class_name(descriptor),
                            location: entry.path.clone(),
                            classes: 1,
                        });
                }
            }
        }
    }
    let mut ordered: Vec<(&String, &(usize, String))> = hosts.first_seen.iter().collect();
    ordered.sort_by_key(|(_, (order, _))| *order);
    let mut network: BTreeMap<usize, NetworkMatch> = BTreeMap::new();
    for (host, (_, location)) in &ordered {
        for matched in signatures.network.matches(host).iter() {
            let tracker = signatures.network_owners[matched];
            let found = network.entry(tracker).or_insert_with(|| NetworkMatch {
                hosts: Vec::new(),
                location: location.clone(),
            });
            if found.hosts.len() < HOSTS_LISTED {
                found.hosts.push((*host).clone());
            }
        }
    }
    let mut trackers: Vec<DetectedTracker> = code
        .keys()
        .chain(network.keys())
        .copied()
        .collect::<std::collections::BTreeSet<usize>>()
        .into_iter()
        .map(|index| DetectedTracker {
            tracker: &database()[index],
            code: code.remove(&index),
            network: network.remove(&index),
        })
        .collect();
    trackers.sort_by(|left, right| left.tracker.name.cmp(right.tracker.name));
    TrackerScan {
        trackers,
        signatures: database().len(),
        database_retrieved: generated::exodus::RETRIEVED,
        classes_checked,
        hosts_checked: ordered.len(),
        skipped: hosts.skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signature_compiles() {
        let signatures = &*SIGNATURES;
        assert!(database().len() >= 400);
        assert!(signatures.code_owners.len() >= 400);
        assert!(signatures.network_owners.len() >= 200);
    }

    #[test]
    fn signatures_match_as_mobsf_matches_them() {
        let signatures = &*SIGNATURES;
        let named = |set: &RegexSet, owners: &[usize], text: &str| -> Vec<&str> {
            set.matches(text)
                .iter()
                .map(|matched| database()[owners[matched]].name)
                .collect()
        };
        // A dotted package prefix matches the slashed descriptor: `.` matches `/`.
        assert!(
            named(
                &signatures.code,
                &signatures.code_owners,
                "Lcom/facebook/appevents/AppEventsLogger;"
            )
            .contains(&"Facebook Analytics")
        );
        assert!(
            named(
                &signatures.network,
                &signatures.network_owners,
                "app.adjust.com"
            )
            .contains(&"Adjust")
        );
    }
}
