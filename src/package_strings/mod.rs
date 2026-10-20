//! Every string an app package holds, walked once for the detectors that read strings: secrets
//! ([`crate::secrets`]) and the URLs and domains trackers are recognised by
//! ([`crate::trackers`]).
//!
//! | Package | Source | [`Source`] |
//! |---|---|---|
//! | APK, AAB | string resources (`resources.arsc`, `resources.pb`), every configuration | `Resource` |
//! | APK, AAB | DEX strings that are not identifiers (literals, static values, annotations), named by the class whose code loads them | `Code` |
//! | APK, AAB | native libraries' read-only data | `Binary` |
//! | APK, AAB | text files (assets, `res/raw`, a bundle module's `root/`) | text file |
//! | IPA | property lists in the bundle, value by value with their key path | `PropertyList` |
//! | IPA | executables' C strings (`__TEXT,__cstring`) | `Binary` |
//! | IPA | other text files in the bundle | text file |
//!
//! Text is bounded: files over 16 MiB, and files past 256 MiB of text per package, are not read
//! and are reported to the visitor ([`Visitor::skipped`]), so its results can say they are
//! incomplete.

pub mod android;
pub(crate) mod extract;
pub mod ios;

/// Text files larger than this are skipped.
pub const MAX_TEXT_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Text read in all, per package.
pub const MAX_TEXT_BYTES: u64 = 256 * 1024 * 1024;

/// A file that should have been read and was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    /// The file.
    pub path: String,
    /// Why.
    pub reason: String,
}

/// Where a string comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// A string resource value.
    Resource,
    /// A DEX string that is not an identifier.
    Code,
    /// A string of a native library or executable.
    Binary,
    /// A string value in a property list.
    PropertyList,
}

/// One string value.
#[derive(Debug, Clone, Copy)]
pub struct PackageString<'a> {
    /// Where it comes from.
    pub source: Source,
    /// The file in the package.
    pub location: &'a str,
    /// Where in the file: `@string/api_key`, a class (`com.example.Config`), a plist key path
    /// (`Keys/API_KEY`).
    pub context: Option<&'a str>,
    /// The key the value is stored under, for heuristics that read key names: a string
    /// resource's name (given with its default configuration's value only: values are
    /// translations of one string), or a property list key.
    pub key: Option<&'a str>,
    /// The string.
    pub text: &'a str,
}

/// What reads a package's strings.
pub trait Visitor {
    /// One string value.
    fn string(&mut self, string: &PackageString<'_>);
    /// A whole text file.
    fn text_file(&mut self, location: &str, text: &str);
    /// A property list about to be walked.
    fn property_list(&mut self, _location: &str) {}
    /// Every file's path, read or not.
    fn file(&mut self, _path: &str) {}
    /// A file that should have been read and was not, and why.
    fn skipped(&mut self, path: &str, reason: &str);
}

/// Two visitors fed by one walk.
pub struct Both<'a, A: Visitor, B: Visitor>(pub &'a mut A, pub &'a mut B);

impl<A: Visitor, B: Visitor> Visitor for Both<'_, A, B> {
    fn string(&mut self, string: &PackageString<'_>) {
        self.0.string(string);
        self.1.string(string);
    }

    fn text_file(&mut self, location: &str, text: &str) {
        self.0.text_file(location, text);
        self.1.text_file(location, text);
    }

    fn property_list(&mut self, location: &str) {
        self.0.property_list(location);
        self.1.property_list(location);
    }

    fn file(&mut self, path: &str) {
        self.0.file(path);
        self.1.file(path);
    }

    fn skipped(&mut self, path: &str, reason: &str) {
        self.0.skipped(path, reason);
        self.1.skipped(path, reason);
    }
}

/// The text budget of one walk.
pub(crate) struct TextBudget {
    used: u64,
}

impl TextBudget {
    pub(crate) fn new() -> Self {
        Self { used: 0 }
    }

    /// Takes `size` bytes from the budget, or says why the file is not read.
    pub(crate) fn take(&mut self, size: u64) -> Result<(), String> {
        if size > MAX_TEXT_FILE_BYTES {
            return Err(format!("{size} bytes: larger than the text file limit"));
        }
        if self.used + size > MAX_TEXT_BYTES {
            return Err("the text budget for this package was spent".to_owned());
        }
        self.used += size;
        Ok(())
    }
}
