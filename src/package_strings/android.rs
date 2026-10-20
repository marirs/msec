//! The strings of APKs and app bundles: resource strings (as MobSF's `android/strings.py` reads
//! them), DEX strings (MobSF reads string literals from jadx's decompiled sources; msec reads the
//! DEX string table directly, see PORTING.md deviation 35), native libraries' strings, and text
//! files MobSF does not read (assets, `res/raw`, a bundle module's `root/`).

use std::collections::HashSet;
use std::io::{Read, Seek};

use super::extract::{as_text, printable_runs};
use super::{PackageString, Source, TextBudget, Visitor};
use crate::android::dex::DexEntry;
use crate::android::native::NativeLibrary;
use crate::android::resources::{EntryValue, ResourceTable};
use crate::android::{Apk, Bundle, Value};
use crate::archive::ZipArchive;
use crate::elf::Elf;

/// `PT_LOAD`.
const PT_LOAD: u32 = 1;
/// `PF_X`.
const PF_X: u32 = 1;

/// Extensions of files that are never text; anything else is read when it sniffs as text.
const BINARY_EXTENSIONS: [&str; 34] = [
    "dex", "so", "arsc", "pb", "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "heif", "avif",
    "ttf", "otf", "woff", "woff2", "mp3", "mp4", "m4a", "aac", "ogg", "oga", "wav", "flac", "webm",
    "mkv", "zip", "jar", "apk", "gz", "tflite", "riv", "lottie",
];

/// Walks an APK's strings.
pub fn walk_apk<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    apk: &Apk,
    visitor: &mut impl Visitor,
) {
    if let Some(Ok(table)) = &apk.resources {
        resource_strings(visitor, "resources.arsc", table);
    }
    for entry in &apk.dex_files {
        dex_strings(visitor, entry);
    }
    native_strings(visitor, archive, &apk.native_libraries);
    text_files(visitor, archive, is_apk_text_candidate);
}

/// Walks an app bundle's strings, module by module.
pub fn walk_bundle<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    bundle: &Bundle,
    visitor: &mut impl Visitor,
) {
    for module in &bundle.modules {
        if let Some(Ok(table)) = &module.resources {
            resource_strings(visitor, &format!("{}/resources.pb", module.name), table);
        }
        for entry in &module.dex_files {
            dex_strings(visitor, entry);
        }
        native_strings(visitor, archive, &module.native_libraries);
    }
    text_files(visitor, archive, is_bundle_text_candidate);
}

/// Every distinct value of every string resource, in every configuration. The resource's name
/// is given as the key with its default configuration's value only (the first value when
/// there is no default): the others are translations of the same string.
fn resource_strings(visitor: &mut impl Visitor, location: &str, table: &ResourceTable) {
    for id in table.ids_of_type("string") {
        let Some(name) = table.name(id) else {
            continue;
        };
        let context = format!("@string/{}", name.entry);
        let values = table.values(id);
        let keyed = values
            .iter()
            .position(|value| value.config.is_default())
            .unwrap_or(0);
        let mut seen: HashSet<String> = HashSet::new();
        for (position, value) in values.into_iter().enumerate() {
            let EntryValue::Simple(Value::String(Some(text))) = value.value else {
                continue;
            };
            let with_key = position == keyed;
            if text.is_empty() || (!seen.insert(text.clone()) && !with_key) {
                continue;
            }
            visitor.string(&PackageString {
                source: Source::Resource,
                location,
                context: Some(&context),
                key: with_key.then_some(name.entry.as_str()),
                text: &text,
            });
        }
    }
}

/// DEX strings that are not identifiers, named by the class whose code loads them.
fn dex_strings(visitor: &mut impl Visitor, entry: &DexEntry) {
    for file in &entry.container.files {
        for (index, caller) in file.literal_strings() {
            let Some(text) = file.string(index) else {
                continue;
            };
            let class = caller
                .and_then(|method| file.method_class(method))
                .map(class_name);
            visitor.string(&PackageString {
                source: Source::Code,
                location: &entry.path,
                context: class.as_deref(),
                key: None,
                text,
            });
        }
    }
}

/// `Lcom/example/Config;` as `com.example.Config`.
pub(crate) fn class_name(descriptor: &str) -> String {
    descriptor
        .strip_prefix('L')
        .and_then(|name| name.strip_suffix(';'))
        .unwrap_or(descriptor)
        .replace('/', ".")
}

/// Strings in each native library's read-only data (its `.rodata` and `.data` sections, or its
/// non-executable loaded segments when it has no section headers; the whole file when it is
/// not ELF), each distinct string once per library.
fn native_strings<R: Read + Seek>(
    visitor: &mut impl Visitor,
    archive: &mut ZipArchive<R>,
    libraries: &[NativeLibrary],
) {
    for library in libraries {
        let bytes = match archive.read_by_name(&library.path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(error) => {
                visitor.skipped(&library.path, &error.to_string());
                continue;
            }
        };
        let ranges = match &library.elf {
            Ok(elf) => data_ranges(elf),
            Err(_) => vec![(0, bytes.len() as u64)],
        };
        let mut seen: HashSet<String> = HashSet::new();
        for (offset, size) in ranges {
            let Some(data) = slice(&bytes, offset, size) else {
                continue;
            };
            for string in printable_runs(data) {
                if !seen.insert(string.clone()) {
                    continue;
                }
                visitor.string(&PackageString {
                    source: Source::Binary,
                    location: &library.path,
                    context: None,
                    key: None,
                    text: &string,
                });
            }
        }
    }
}

fn data_ranges(elf: &Elf) -> Vec<(u64, u64)> {
    if !elf.sections.is_empty() {
        return elf
            .sections
            .iter()
            .filter(|section| {
                section.name.starts_with(".rodata")
                    || section.name == ".data"
                    || section.name == ".data.rel.ro"
            })
            .map(|section| (section.offset, section.size))
            .collect();
    }
    elf.segments
        .iter()
        .filter(|segment| segment.kind == PT_LOAD && segment.flags & PF_X == 0)
        .map(|segment| (segment.offset, segment.file_size))
        .collect()
}

fn slice(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(size).ok()?)?;
    bytes.get(start..end.min(bytes.len()))
}

/// APK files worth reading as text: not code, not resources compiled by aapt, not signature
/// files.
fn is_apk_text_candidate(path: &str) -> bool {
    path != "AndroidManifest.xml"
        && !path.starts_with("META-INF/")
        && (!path.starts_with("res/") || path.starts_with("res/raw/"))
}

/// Bundle files worth reading as text: a module's assets, raw resources and `root/` files.
fn is_bundle_text_candidate(path: &str) -> bool {
    let Some((module, rest)) = path.split_once('/') else {
        return false;
    };
    module != "META-INF"
        && module != "BUNDLE-METADATA"
        && (rest.starts_with("assets/")
            || rest.starts_with("res/raw/")
            || rest.starts_with("root/"))
}

fn has_binary_extension(path: &str) -> bool {
    path.rsplit_once('.').is_some_and(|(_, extension)| {
        BINARY_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
    })
}

/// Every entry's path to the visitor, and the text files among them, whole.
fn text_files<R: Read + Seek>(
    visitor: &mut impl Visitor,
    archive: &mut ZipArchive<R>,
    candidate: fn(&str) -> bool,
) {
    let entries: Vec<(usize, String, u64)> = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory)
        .map(|entry| (entry.index, entry.name.clone(), entry.uncompressed_size))
        .collect();
    let mut budget = TextBudget::new();
    for (index, path, size) in entries {
        visitor.file(&path);
        if !candidate(&path) || has_binary_extension(&path) {
            continue;
        }
        if let Err(reason) = budget.take(size) {
            visitor.skipped(&path, &reason);
            continue;
        }
        match archive.read(index) {
            Ok(bytes) => {
                if let Some(text) = as_text(&bytes) {
                    visitor.text_file(&path, &text);
                }
            }
            Err(error) => visitor.skipped(&path, &error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates() {
        assert!(is_apk_text_candidate("assets/config.json"));
        assert!(is_apk_text_candidate("res/raw/keys.txt"));
        assert!(!is_apk_text_candidate("res/layout/main.xml"));
        assert!(!is_apk_text_candidate("META-INF/CERT.SF"));
        assert!(is_bundle_text_candidate("base/assets/config.json"));
        assert!(is_bundle_text_candidate("feature/root/notes.txt"));
        assert!(!is_bundle_text_candidate(
            "base/manifest/AndroidManifest.xml"
        ));
        assert!(!is_bundle_text_candidate("BUNDLE-METADATA/x/mapping.txt"));
        assert!(has_binary_extension("assets/logo.PNG"));
        assert_eq!(class_name("Lcom/example/Config;"), "com.example.Config");
    }
}
