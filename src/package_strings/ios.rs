//! The strings of an IPA's app bundle: property lists (as MobSF's `ios/plist_analysis.py::
//! get_plist_secrets` reads them), the C strings of every executable (MobSF's `ios/strings.py`
//! reads the main executable's, frameworks' and libraries' strings), and the bundle's other text
//! files (MobSF reads them for URLs).

use std::collections::HashSet;
use std::io::{Read, Seek};

use super::extract::{as_text, c_strings, printable_runs};
use super::{PackageString, Source, TextBudget, Visitor};
use crate::archive::ZipArchive;
use crate::ios::{BundleBinary, Ipa};
use crate::plist::{self, Value};

/// Files in a bundle that are never text, or whose text is signatures and hashes.
const SKIPPED_EXTENSIONS: [&str; 22] = [
    "car",
    "nib",
    "storyboardc",
    "mobileprovision",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "heic",
    "pdf",
    "ttf",
    "otf",
    "woff",
    "woff2",
    "mp3",
    "mp4",
    "m4a",
    "caf",
    "wav",
    "mov",
    "mlmodelc",
    "dylib",
];

/// Walks the strings of the IPA's app bundle; nothing without one.
pub fn walk_ipa<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    ipa: &Ipa,
    visitor: &mut impl Visitor,
) {
    let Some(app) = &ipa.app else {
        return;
    };
    let entries: Vec<(usize, String, u64)> = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory && entry.name.starts_with(&app.path))
        .map(|entry| (entry.index, entry.name.clone(), entry.uncompressed_size))
        .collect();
    let mut budget = TextBudget::new();
    for (index, path, size) in entries {
        visitor.file(&path);
        if let Some(binary) = app.binaries.iter().find(|binary| binary.path == path) {
            executable_strings(visitor, archive, binary);
            continue;
        }
        if path.contains("/_CodeSignature/") || skipped_extension(&path) {
            continue;
        }
        if let Err(reason) = budget.take(size) {
            visitor.skipped(&path, &reason);
            continue;
        }
        let bytes = match archive.read(index) {
            Ok(bytes) => bytes,
            Err(error) => {
                visitor.skipped(&path, &error.to_string());
                continue;
            }
        };
        if path.ends_with(".plist")
            && let Ok(parsed) = plist::parse(&bytes)
        {
            property_list(visitor, &path, &parsed.root);
        } else if let Some(text) = as_text(&bytes) {
            visitor.text_file(&path, &text);
        }
    }
}

fn skipped_extension(path: &str) -> bool {
    path.rsplit_once('.').is_some_and(|(_, extension)| {
        SKIPPED_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
    })
}

/// Every string in a property list, with its key path and the key it is stored under. The
/// walk keeps its own stack: property lists nest up to 513 levels.
fn property_list(visitor: &mut impl Visitor, location: &str, root: &Value) {
    visitor.property_list(location);
    let mut stack: Vec<(String, Option<String>, &Value)> = vec![(String::new(), None, root)];
    while let Some((path, key, value)) = stack.pop() {
        match value {
            Value::String(text) => {
                if text.is_empty() {
                    continue;
                }
                visitor.string(&PackageString {
                    source: Source::PropertyList,
                    location,
                    context: (!path.is_empty()).then_some(path.as_str()),
                    key: key.as_deref(),
                    text,
                });
            }
            Value::Dictionary(dictionary) => {
                // Reversed, so the walk visits keys in the order the file lists them.
                let children: Vec<_> = dictionary.iter().collect();
                for (child_key, child) in children.into_iter().rev() {
                    let child_path = if path.is_empty() {
                        child_key.to_owned()
                    } else {
                        format!("{path}/{child_key}")
                    };
                    stack.push((child_path, Some(child_key.to_owned()), child));
                }
            }
            Value::Array(items) | Value::Set(items) => {
                for (position, item) in items.iter().enumerate().rev() {
                    stack.push((format!("{path}[{position}]"), key.clone(), item));
                }
            }
            _ => {}
        }
    }
}

/// C strings (`__TEXT,__cstring`) of every architecture of an executable, each once; printable
/// runs of the whole file when it is not Mach-O.
fn executable_strings<R: Read + Seek>(
    visitor: &mut impl Visitor,
    archive: &mut ZipArchive<R>,
    binary: &BundleBinary,
) {
    let bytes = match archive.read_by_name(&binary.path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return,
        Err(error) => {
            visitor.skipped(&binary.path, &error.to_string());
            return;
        }
    };
    let mut strings: Vec<String> = Vec::new();
    match &binary.macho {
        Ok(file) => {
            for slice in &file.slices {
                let Ok(image) = &slice.image else {
                    continue;
                };
                let sections = image
                    .segments
                    .iter()
                    .flat_map(|segment| &segment.sections)
                    .filter(|section| section.segment == "__TEXT" && section.name == "__cstring");
                for section in sections {
                    let start = slice.offset.saturating_add(u64::from(section.offset));
                    let Some(data) = usize::try_from(start)
                        .ok()
                        .zip(usize::try_from(section.size).ok())
                        .and_then(|(start, size)| bytes.get(start..start.checked_add(size)?))
                    else {
                        continue;
                    };
                    strings.extend(c_strings(data));
                }
            }
        }
        Err(_) => strings = printable_runs(&bytes),
    }
    let mut seen: HashSet<String> = HashSet::new();
    for string in strings {
        if !seen.insert(string.clone()) {
            continue;
        }
        visitor.string(&PackageString {
            source: Source::Binary,
            location: &binary.path,
            context: None,
            key: None,
            text: &string,
        });
    }
}
