//! The DEX files of an APK, read in the order Android loads them, and what they hold together.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek};

use super::{DexContainer, DexError, parse};
use crate::archive::ZipArchive;

/// Most uncompressed DEX bytes read from one package. Large apps ship tens of megabytes; this
/// stops a package of many maximum-size files from holding gigabytes in memory.
const MAX_PACKAGE_DEX_BYTES: u64 = 1024 * 1024 * 1024;
/// Shadowed classes listed by name; the rest are counted.
const MAX_SHADOWED_LISTED: usize = 100;

/// One root `classes*.dex` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexEntry {
    /// Entry name (`classes2.dex`).
    pub path: String,
    /// Uncompressed size.
    pub size: u64,
    /// What was read.
    pub container: DexContainer,
}

/// Reads the given entries (root `classes*.dex` names, in load order, as
/// [`Inventory::dex_files`](crate::android::Inventory) lists them).
pub fn read_dex_files<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    names: &[String],
) -> Vec<DexEntry> {
    let mut read_so_far: u64 = 0;
    names
        .iter()
        .filter_map(|name| {
            let entry = archive.find(name)?;
            let (index, size) = (entry.index, entry.uncompressed_size);
            let container = if read_so_far.saturating_add(size) > MAX_PACKAGE_DEX_BYTES {
                failed(DexError::PackageBudgetExhausted)
            } else {
                match archive.read(index) {
                    Ok(bytes) => {
                        read_so_far = read_so_far.saturating_add(bytes.len() as u64);
                        parse(&bytes)
                    }
                    Err(error) => failed(DexError::Unreadable(error.to_string())),
                }
            };
            Some(DexEntry {
                path: name.clone(),
                size,
                container,
            })
        })
        .collect()
}

fn failed(error: DexError) -> DexContainer {
    DexContainer {
        files: Vec::new(),
        error: Some(error),
    }
}

/// What the DEX files of a package hold together.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodeSummary {
    /// Logical DEX files read (one per `.dex`, except version 041 containers).
    pub logical_files: usize,
    /// Classes Android can load: a class defined in several files counts once.
    pub classes: usize,
    /// Method references (`method_ids`), summed over files. The 64K limit applies per file.
    pub method_references: u64,
    /// Classes per package, most first, then by name. The default package is `""`.
    pub packages: Vec<PackageCount>,
    /// Classes defined again in a later file, up to 100. Android loads the
    /// first definition; the later ones never run.
    pub shadowed: Vec<ShadowedClass>,
    /// All shadowed classes, listed or not.
    pub shadowed_count: usize,
    /// Every DEX file was read in full.
    pub complete: bool,
}

/// Number of classes in one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageCount {
    /// Dotted package name (`com.example.app`); `""` for the default package.
    pub package: String,
    /// Classes Android can load from it.
    pub classes: usize,
}

/// A class defined in more than one DEX file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowedClass {
    /// Descriptor (`Lcom/example/Config;`).
    pub descriptor: String,
    /// The file Android loads it from.
    pub loaded_from: String,
    /// A later file whose definition is never used.
    pub shadowed_in: String,
}

/// Summarises DEX files read with [`read_dex_files`], in load order.
pub fn summarise(entries: &[DexEntry]) -> CodeSummary {
    let mut summary = CodeSummary {
        complete: entries.iter().all(|entry| entry.container.complete()),
        ..CodeSummary::default()
    };
    // Descriptor to the entry Android loads it from.
    let mut loaded: HashMap<&str, &str> = HashMap::new();
    let mut packages: BTreeMap<String, usize> = BTreeMap::new();
    for entry in entries {
        for file in &entry.container.files {
            summary.logical_files += 1;
            summary.method_references += u64::from(file.header.method_ids.count);
            for class in &file.classes {
                let Some(descriptor) = file.class_descriptor(class) else {
                    continue;
                };
                match loaded.get(descriptor) {
                    // A repeat within one file is a DexAnomalyKind::DuplicateClass already.
                    Some(&first) if first == entry.path => {}
                    Some(&first) => {
                        summary.shadowed_count += 1;
                        if summary.shadowed.len() < MAX_SHADOWED_LISTED {
                            summary.shadowed.push(ShadowedClass {
                                descriptor: descriptor.to_owned(),
                                loaded_from: first.to_owned(),
                                shadowed_in: entry.path.clone(),
                            });
                        }
                    }
                    None => {
                        loaded.insert(descriptor, &entry.path);
                        if let Some(package) = package_of(descriptor) {
                            *packages.entry(package).or_default() += 1;
                        }
                    }
                }
            }
        }
    }
    summary.classes = loaded.len();
    summary.packages = packages
        .into_iter()
        .map(|(package, classes)| PackageCount { package, classes })
        .collect();
    // Stable: equal counts stay in name order.
    summary
        .packages
        .sort_by_key(|count| std::cmp::Reverse(count.classes));
    summary
}

/// `Lcom/example/Main$Inner;` is in `com.example`; `LMain;` in the default package (`""`).
/// `None` for a descriptor that is not a class.
pub(crate) fn package_of(descriptor: &str) -> Option<String> {
    let name = descriptor.strip_prefix('L')?.strip_suffix(';')?;
    Some(
        name.rsplit_once('/')
            .map_or_else(String::new, |(package, _)| package.replace('/', ".")),
    )
}

#[cfg(test)]
mod tests {
    use super::package_of;

    #[test]
    fn packages_come_from_class_descriptors() {
        assert_eq!(
            package_of("Lcom/example/Main$Inner;").as_deref(),
            Some("com.example")
        );
        assert_eq!(package_of("LMain;").as_deref(), Some(""));
        assert_eq!(package_of("[Lcom/example/Main;"), None);
        assert_eq!(package_of("I"), None);
    }
}
