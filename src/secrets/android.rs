//! Secrets in APKs and app bundles: resource strings (MobSF `android/strings.py`), DEX strings
//! (MobSF reads string literals from jadx's decompiled sources; msec reads the DEX string table
//! directly, see PORTING.md deviation 35), native libraries' strings, and text files MobSF does
//! not read (assets, `res/raw`, a bundle module's `root/`).

use std::collections::HashSet;
use std::io::{Read, Seek};

use super::strings::{as_text, printable_runs};
use super::{Collector, MAX_TEXT_BYTES, MAX_TEXT_FILE_BYTES, SecretScan, ValueChecks};
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

/// Secrets in an APK.
pub fn scan_apk<R: Read + Seek>(archive: &mut ZipArchive<R>, apk: &Apk) -> SecretScan {
    let mut collector = Collector::new();
    if let Some(Ok(table)) = &apk.resources {
        resource_strings(&mut collector, "resources.arsc", table);
    }
    for entry in &apk.dex_files {
        dex_strings(&mut collector, entry);
    }
    native_strings(&mut collector, archive, &apk.native_libraries);
    text_files(&mut collector, archive, is_apk_text_candidate);
    collector.finish()
}

/// Secrets in an app bundle, module by module.
pub fn scan_bundle<R: Read + Seek>(archive: &mut ZipArchive<R>, bundle: &Bundle) -> SecretScan {
    let mut collector = Collector::new();
    for module in &bundle.modules {
        if let Some(Ok(table)) = &module.resources {
            resource_strings(
                &mut collector,
                &format!("{}/resources.pb", module.name),
                table,
            );
        }
        for entry in &module.dex_files {
            dex_strings(&mut collector, entry);
        }
        native_strings(&mut collector, archive, &module.native_libraries);
    }
    text_files(&mut collector, archive, is_bundle_text_candidate);
    collector.finish()
}

/// Every string resource in every configuration: known formats in each, and MobSF's key-name
/// heuristic on the resource's name in the default configuration only (the first one when
/// there is no default). MobSF applies the heuristic to every translation too, which reports a
/// library's "Password" label once per language; a secret is not translated (PORTING.md
/// deviation 36).
fn resource_strings(collector: &mut Collector, location: &str, table: &ResourceTable) {
    for id in table.ids_of_type("string") {
        let Some(name) = table.name(id) else {
            continue;
        };
        let context = format!("@string/{}", name.entry);
        let values = table.values(id);
        let heuristic_config = values
            .iter()
            .position(|value| value.config.is_default())
            .unwrap_or(0);
        let mut seen: HashSet<String> = HashSet::new();
        for (position, value) in values.into_iter().enumerate() {
            let EntryValue::Simple(Value::String(Some(text))) = value.value else {
                continue;
            };
            let key_checked = position == heuristic_config;
            if text.is_empty() || (!seen.insert(text.clone()) && !key_checked) {
                continue;
            }
            collector.counts().resource_strings += 1;
            collector.value(
                location,
                Some(&context),
                &text,
                ValueChecks {
                    key: key_checked.then_some(name.entry.as_str()),
                    entropy: false,
                },
            );
        }
    }
}

/// MobSF's filter on code strings (`shared_func.py::strings_and_entropies`): at least four
/// characters, starting with a letter or digit, not an escaped NUL or a `com.google.` name,
/// and not a JVM or Android path.
fn mobsf_code_string(text: &str) -> bool {
    text.chars().count() >= 4
        && text.chars().next().is_some_and(char::is_alphanumeric)
        && !text.contains("\\u0")
        && !text.contains("com.google.")
        && !(text.contains('/')
            && ["Ljava", "Lkotlin", "kotlin", "android"]
                .iter()
                .any(|word| text.contains(word)))
}

/// DEX strings that are not identifiers: known formats and MobSF's entropy heuristic, named
/// by the class whose code loads them.
fn dex_strings(collector: &mut Collector, entry: &DexEntry) {
    for file in &entry.container.files {
        for (index, caller) in file.literal_strings() {
            let Some(text) = file.string(index) else {
                continue;
            };
            if !mobsf_code_string(text) {
                continue;
            }
            collector.counts().code_strings += 1;
            let class = caller
                .and_then(|method| file.method_class(method))
                .map(class_name);
            collector.value(
                &entry.path,
                class.as_deref(),
                text,
                ValueChecks {
                    key: None,
                    entropy: true,
                },
            );
        }
    }
}

/// `Lcom/example/Config;` as `com.example.Config`.
fn class_name(descriptor: &str) -> String {
    descriptor
        .strip_prefix('L')
        .and_then(|name| name.strip_suffix(';'))
        .unwrap_or(descriptor)
        .replace('/', ".")
}

/// Strings in each native library's read-only data (its `.rodata` and `.data` sections, or
/// its non-executable loaded segments when it has no section headers; the whole file when it
/// is not ELF): known formats and MobSF's entropy heuristic.
fn native_strings<R: Read + Seek>(
    collector: &mut Collector,
    archive: &mut ZipArchive<R>,
    libraries: &[NativeLibrary],
) {
    for library in libraries {
        let bytes = match archive.read_by_name(&library.path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(error) => {
                collector.skip(&library.path, error.to_string());
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
                collector.counts().binary_strings += 1;
                collector.value(
                    &library.path,
                    None,
                    &string,
                    ValueChecks {
                        key: None,
                        entropy: true,
                    },
                );
            }
        }
    }
}

fn data_ranges(elf: &Elf) -> Vec<(u64, u64)> {
    let sections: Vec<(u64, u64)> = elf
        .sections
        .iter()
        .filter(|section| {
            section.name.starts_with(".rodata")
                || section.name == ".data"
                || section.name == ".data.rel.ro"
        })
        .map(|section| (section.offset, section.size))
        .collect();
    if !elf.sections.is_empty() {
        return sections;
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

/// Text files among the archive's entries: known formats, line by line; and file names
/// gitleaks flags (PKCS #12 key stores) among every entry.
fn text_files<R: Read + Seek>(
    collector: &mut Collector,
    archive: &mut ZipArchive<R>,
    candidate: fn(&str) -> bool,
) {
    let entries: Vec<(usize, String, u64)> = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory)
        .map(|entry| (entry.index, entry.name.clone(), entry.uncompressed_size))
        .collect();
    for (index, path, size) in entries {
        collector.file_name(&path);
        if !candidate(&path) || has_binary_extension(&path) {
            continue;
        }
        if size > MAX_TEXT_FILE_BYTES {
            collector.skip(
                &path,
                format!("{size} bytes: larger than the text file limit"),
            );
            continue;
        }
        if collector.text_bytes + size > MAX_TEXT_BYTES {
            collector.skip(&path, "the text budget for this package was spent");
            continue;
        }
        collector.text_bytes += size;
        match archive.read(index) {
            Ok(bytes) => {
                if let Some(text) = as_text(&bytes) {
                    collector.text_file(&path, &text);
                }
            }
            Err(error) => collector.skip(&path, error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobsf_code_string_filter() {
        assert!(mobsf_code_string("abcd"));
        assert!(!mobsf_code_string("abc"));
        assert!(!mobsf_code_string("_private"));
        assert!(!mobsf_code_string("com.google.android.gms"));
        assert!(!mobsf_code_string("Ljava/lang/String;"));
        assert!(mobsf_code_string("kotlin is fine without a slash"));
        assert_eq!(class_name("Lcom/example/Config;"), "com.example.Config");
    }

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
    }
}
