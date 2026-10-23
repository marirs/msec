//! The executables of an app bundle and of its components, read as Mach-O, with their code
//! signatures checked: every page hash (unless the App Store encrypted the image), the
//! requirements and entitlements slots, and the two slots that seal the bundle itself
//! (`Info.plist` and `_CodeSignature/CodeResources`), against the bundle's own files.
//!
//! A CMS signature is checked over the primary CodeDirectory, with its certificate chain
//! ([`crate::macho::signer`]). What this does not check: the resource seal's contents
//! (each file CodeResources lists), and nested code's own seals beyond its executable. A
//! signature whose hashes all match shows the binary and its sealed files are unchanged since
//! signing; the signer check shows whose key signed it and whether Apple issued that key's
//! certificate.

use std::io::{Read, Seek};

use super::analysis::WEBVIEW_FILE_ORIGIN_KEYS;
use super::purpose_strings::{ResourceUse, uses_in};
use super::required_reason::{ApiUse, apis_in};
use super::store_leads::{ACCOUNT_SELECTORS, PRIVATE_FRAMEWORKS};
use crate::archive::ZipArchive;
use crate::macho::signature::{
    CodeSignature, SLOT_DER_ENTITLEMENTS, SLOT_ENTITLEMENTS, SLOT_INFO_PLIST, SLOT_REQUIREMENTS,
    SLOT_RESOURCES,
};
use crate::macho::signer::Signer;
use crate::macho::{MachFile, MachO, MachOAnomalyKind, command_name, parse};
use crate::plist::{Plist, PlistError};

/// Largest executable read: real ones run to a few hundred megabytes.
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// What an executable is to the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryRole {
    /// The app's main executable (`CFBundleExecutable`).
    MainExecutable,
    /// A component's executable.
    Component(super::ComponentKind),
}

/// An executable or library in the bundle.
#[derive(Debug, Clone, PartialEq)]
pub struct BundleBinary {
    /// Its path in the archive.
    pub path: String,
    /// What it is to the bundle.
    pub role: BinaryRole,
    /// Its size, as the archive declares it.
    pub size: u64,
    /// The Mach-O file, or why it could not be read.
    pub macho: Result<MachFile, String>,
    /// The signature checks of each slice, in slice order (empty when not read).
    pub signatures: Vec<SignatureCheck>,
    /// The required-reason APIs any slice uses (see [`super::required_reason`]).
    pub required_reason_apis: Vec<ApiUse>,
    /// The protected resources any slice's code uses, by imports and method names (see
    /// [`super::purpose_strings`]; entitlements are read from [`Self::entitlements`]).
    pub protected_resource_uses: Vec<ResourceUse>,
    /// `__TEXT` sections msec reads (`__cstring`, `__objc_methname`) that the App Store
    /// encrypted in some slice (FairPlay), sorted: what they hold was not read, so the checks
    /// that read them are incomplete for this executable.
    pub encrypted_sections: Vec<String>,
    /// `__TEXT` sections msec reads whose range lies outside their slice (a truncated or
    /// malformed file), sorted: likewise not read.
    pub unreadable_sections: Vec<String>,
    /// The WebKit preferences relaxing file origin rules that a C string names
    /// ([`super::analysis::WEBVIEW_FILE_ORIGIN_KEYS`]), sorted.
    pub webview_file_origin_keys: Vec<String>,
    /// C strings naming a path under /System/Library/PrivateFrameworks, sorted.
    pub private_framework_strings: Vec<String>,
    /// Objective-C selectors that create or delete accounts
    /// ([`super::store_leads::ACCOUNT_SELECTORS`]) among the method names, sorted.
    pub account_selectors: Vec<String>,
}

impl BundleBinary {
    /// The entitlements of the first slice that has them.
    pub fn entitlements(&self) -> Option<&Result<Plist, PlistError>> {
        self.images()
            .find_map(|image| match &image.signature {
                Some(Ok(signature)) => signature.entitlements.as_ref(),
                _ => None,
            })
            .map(|entitlements| &entitlements.plist)
    }

    /// The images read, in slice order.
    pub fn images(&self) -> impl Iterator<Item = &MachO> {
        self.macho
            .as_ref()
            .ok()
            .into_iter()
            .flat_map(|file| &file.slices)
            .filter_map(|slice| slice.image.as_ref().ok())
    }
}

/// One slice's code signature, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    /// `arm64`, `arm64e`, ...
    pub architecture: String,
    /// What was found: no signature, an unreadable one, ad hoc, or with a CMS signature.
    pub kind: SignatureKind,
    /// The signing identifier.
    pub identifier: Option<String>,
    /// The team identifier.
    pub team_id: Option<String>,
    /// The CDHash.
    pub cdhash: Option<String>,
    /// Every page hash matches; `None` when not checked (no signature, encrypted image).
    pub pages: Option<bool>,
    /// Pages whose hash differs (first 32).
    pub mismatched_pages: Vec<usize>,
    /// The sealed `Info.plist` (the bundle's, or a loose binary's embedded one: [`Sealing`])
    /// matches its slot; `None` when the slot is empty or there is no such plist.
    pub info_plist: Option<bool>,
    /// The bundle's `_CodeSignature/CodeResources` matches its slot; `None` likewise, and for a
    /// binary sealed on its own.
    pub resources: Option<bool>,
    /// The signature's own requirements and entitlements match their slots; `None` when none
    /// is sealed.
    pub embedded_blobs: Option<bool>,
    /// Who signed it, for a signature with a CMS signature: whether that verifies over the
    /// primary CodeDirectory, the certificate chain, and whether it ends at Apple's root.
    pub signer: Option<Signer>,
    /// Why some checks did not run.
    pub note: Option<String>,
}

impl SignatureCheck {
    /// Every check that ran passed, and the pages were checked.
    pub fn valid(&self) -> bool {
        self.pages == Some(true)
            && self.info_plist != Some(false)
            && self.resources != Some(false)
            && self.embedded_blobs != Some(false)
    }
}

/// How a slice is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureKind {
    /// No `LC_CODE_SIGNATURE`.
    Unsigned,
    /// A signature msec could not read, with why.
    Unreadable(String),
    /// Ad hoc: no certificate (development tools and the linker sign this way).
    AdHoc,
    /// Signed with a certificate (a CMS signature is present; see [`SignatureCheck::signer`]).
    Certificate,
}

/// What a binary's signature seals besides its code (special slots 1 and 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sealing<'a> {
    /// The executable of a bundle: the bundle's `Info.plist` and
    /// `_CodeSignature/CodeResources`, when the bundle has them.
    Bundle {
        /// The bundle's `Info.plist`.
        info_plist: Option<&'a [u8]>,
        /// The bundle's `_CodeSignature/CodeResources`.
        resources: Option<&'a [u8]>,
    },
    /// A binary sealed on its own (a loose library, a lone file): the Info.plist embedded in its
    /// `__TEXT,__info_plist` section, as codesign reads it, and no resources. Apple's Swift
    /// runtime libraries bind such an Info.plist; checking them against the app's would report
    /// every one as changed after signing.
    Itself,
}

/// Reads one executable and checks each slice's signature against the bundle at `bundle`
/// (directory with a trailing slash), or against itself when `bundle` is `None` (a loose
/// library).
pub(super) fn read_binary<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    path: &str,
    role: BinaryRole,
    bundle: Option<&str>,
) -> BundleBinary {
    let mut binary = BundleBinary {
        path: path.to_owned(),
        role,
        size: 0,
        macho: Err("not in the archive".to_owned()),
        signatures: Vec::new(),
        required_reason_apis: Vec::new(),
        protected_resource_uses: Vec::new(),
        encrypted_sections: Vec::new(),
        unreadable_sections: Vec::new(),
        webview_file_origin_keys: Vec::new(),
        private_framework_strings: Vec::new(),
        account_selectors: Vec::new(),
    };
    let Some(entry) = archive.find(path) else {
        return binary;
    };
    binary.size = entry.uncompressed_size;
    if entry.uncompressed_size > MAX_BINARY_BYTES {
        binary.macho = Err(format!("larger than {MAX_BINARY_BYTES} bytes: not read"));
        return binary;
    }
    let index = entry.index;
    let bytes = match archive.read(index) {
        Ok(bytes) => bytes,
        Err(error) => {
            binary.macho = Err(error.to_string());
            return binary;
        }
    };
    let Some(bundle) = bundle else {
        return BundleBinary::from_bytes(path, role, &bytes, Sealing::Itself);
    };
    let info_plist = archive
        .read_by_name(&format!("{bundle}Info.plist"))
        .ok()
        .flatten();
    let resources = archive
        .read_by_name(&format!("{bundle}_CodeSignature/CodeResources"))
        .ok()
        .flatten();
    let sealing = Sealing::Bundle {
        info_plist: info_plist.as_deref(),
        resources: resources.as_deref(),
    };
    BundleBinary::from_bytes(path, role, &bytes, sealing)
}

impl BundleBinary {
    /// Reads an executable from its bytes, checking each slice's signature against what
    /// seals it (`sealing`).
    pub fn from_bytes(path: &str, role: BinaryRole, bytes: &[u8], sealing: Sealing<'_>) -> Self {
        let mut binary = BundleBinary {
            path: path.to_owned(),
            role,
            size: bytes.len() as u64,
            macho: Err(String::new()),
            signatures: Vec::new(),
            required_reason_apis: Vec::new(),
            protected_resource_uses: Vec::new(),
            encrypted_sections: Vec::new(),
            unreadable_sections: Vec::new(),
            webview_file_origin_keys: Vec::new(),
            private_framework_strings: Vec::new(),
            account_selectors: Vec::new(),
        };
        let file = match parse(bytes) {
            Ok(file) => file,
            Err(error) => {
                binary.macho = Err(error.to_string());
                return binary;
            }
        };
        for slice in &file.slices {
            let Ok(image) = &slice.image else {
                continue;
            };
            let start = slice.offset as usize;
            let slice_bytes = &bytes[start..start + slice.size as usize];
            binary
                .signatures
                .push(check(slice.architecture(), image, slice_bytes, sealing));
            for name in ENCRYPTABLE_SECTIONS {
                if text_sections(image, name).any(|section| image.section_encrypted(section)) {
                    binary.encrypted_sections.push(name.to_owned());
                } else if text_sections(image, name).next().is_some()
                    && section(image, slice_bytes, name).is_none()
                {
                    binary.unreadable_sections.push(name.to_owned());
                }
            }
            let c_strings = text_sections(image, "__cstring")
                .all(|section| !image.section_encrypted(section))
                .then(|| section(image, slice_bytes, "__cstring"))
                .flatten();
            if let Some(c_strings) = c_strings {
                for string in c_strings
                    .split(|byte| *byte == 0)
                    .filter_map(|string| std::str::from_utf8(string).ok())
                {
                    if WEBVIEW_FILE_ORIGIN_KEYS.contains(&string) {
                        binary.webview_file_origin_keys.push(string.to_owned());
                    }
                    if string.starts_with(PRIVATE_FRAMEWORKS) {
                        binary.private_framework_strings.push(string.to_owned());
                    }
                }
            }
            // Encrypted method names are ciphertext: imports are still read (the symbol
            // table is never encrypted), selectors are not, which `encrypted_sections` records.
            let method_names = text_sections(image, "__objc_methname")
                .all(|section| !image.section_encrypted(section))
                .then(|| section(image, slice_bytes, "__objc_methname"))
                .flatten();
            if let Some(method_names) = method_names {
                binary.account_selectors.extend(
                    method_names
                        .split(|byte| *byte == 0)
                        .filter_map(|name| std::str::from_utf8(name).ok())
                        .filter(|name| ACCOUNT_SELECTORS.contains(name))
                        .map(str::to_owned),
                );
            }
            binary
                .required_reason_apis
                .extend(apis_in(image, method_names));
            binary
                .protected_resource_uses
                .extend(uses_in(image, method_names));
        }
        binary.protected_resource_uses.sort();
        binary
            .protected_resource_uses
            .dedup_by_key(|resource_use| resource_use.requirement);
        binary
            .required_reason_apis
            .sort_by(|left, right| (left.category, left.api).cmp(&(right.category, right.api)));
        binary.required_reason_apis.dedup();
        binary.encrypted_sections.sort();
        binary.encrypted_sections.dedup();
        binary.unreadable_sections.sort();
        binary.unreadable_sections.dedup();
        binary.webview_file_origin_keys.sort();
        binary.webview_file_origin_keys.dedup();
        binary.private_framework_strings.sort();
        binary.private_framework_strings.dedup();
        binary.account_selectors.sort();
        binary.account_selectors.dedup();
        binary.macho = Ok(file);
        binary
    }
}

/// The `__TEXT` sections msec reads content from, which the App Store's encryption can hide.
const ENCRYPTABLE_SECTIONS: [&str; 2] = ["__cstring", "__objc_methname"];

/// The `__TEXT` sections named `name`.
fn text_sections<'image>(
    image: &'image MachO,
    name: &'image str,
) -> impl Iterator<Item = &'image crate::macho::Section> {
    image
        .segments
        .iter()
        .flat_map(|segment| &segment.sections)
        .filter(move |section| section.segment == "__TEXT" && section.name == name)
}

/// A `__TEXT` section's bytes within its slice, when the slice holds them.
fn section<'data>(image: &MachO, slice: &'data [u8], name: &str) -> Option<&'data [u8]> {
    let section = text_sections(image, name).next()?;
    let start = usize::try_from(section.offset).ok()?;
    let size = usize::try_from(section.size).ok()?;
    slice.get(start..start.checked_add(size)?)
}

fn check(
    architecture: String,
    image: &MachO,
    bytes: &[u8],
    sealing: Sealing<'_>,
) -> SignatureCheck {
    let mut result = SignatureCheck {
        architecture,
        kind: SignatureKind::Unsigned,
        identifier: None,
        team_id: None,
        cdhash: None,
        pages: None,
        mismatched_pages: Vec::new(),
        info_plist: None,
        resources: None,
        embedded_blobs: None,
        signer: None,
        note: None,
    };
    let signature = match &image.signature {
        // LC_CODE_SIGNATURE present but pointing outside the file (a truncated executable;
        // the parser keeps no range for it and records the anomaly): signed, but the
        // signature cannot be read, which is not the same as unsigned.
        None if image.anomalies.iter().any(|anomaly| {
            matches!(
                anomaly.kind,
                MachOAnomalyKind::LinkeditDataOutOfBounds { command }
                    if command_name(command) == "LC_CODE_SIGNATURE"
            )
        }) =>
        {
            result.kind =
                SignatureKind::Unreadable("LC_CODE_SIGNATURE points outside the file".to_owned());
            return result;
        }
        None => return result,
        Some(Err(error)) => {
            result.kind = SignatureKind::Unreadable(error.to_string());
            return result;
        }
        Some(Ok(signature)) => signature,
    };
    let Some(directory) = signature.best_code_directory() else {
        result.kind = SignatureKind::Unreadable("no readable CodeDirectory".to_owned());
        return result;
    };
    result.kind = if signature.has_cms_signature() {
        SignatureKind::Certificate
    } else {
        SignatureKind::AdHoc
    };
    // The CMS signature signs the CodeDirectory in slot 0, whichever is best for page hashes.
    result.signer = signature
        .cms
        .as_deref()
        .filter(|cms| !cms.is_empty())
        .map(|cms| {
            let primary = signature
                .code_directories
                .iter()
                .find(|directory| directory.slot == 0)
                .map(|directory| directory.bytes());
            Signer::check(cms, primary)
        });
    result.identifier = Some(directory.identifier.clone());
    result.team_id = directory.team_id.clone();
    result.cdhash = directory.cdhash();
    if image
        .encryption
        .is_some_and(|encryption| encryption.encrypted())
    {
        result.note = Some("encrypted by the App Store: page hashes cannot be checked".to_owned());
    } else {
        let pages = directory.verify_pages(bytes);
        result.pages = Some(pages.valid());
        result.mismatched_pages = pages.mismatched;
        if let Some(problem) = pages.problem {
            result.note = Some(problem.to_owned());
        }
    }
    let (info_plist, resources) = match sealing {
        Sealing::Bundle {
            info_plist,
            resources,
        } => (info_plist, resources),
        Sealing::Itself => (section(image, bytes, "__info_plist"), None),
    };
    result.info_plist =
        info_plist.and_then(|plist| directory.verify_special(SLOT_INFO_PLIST, plist));
    result.resources =
        resources.and_then(|sealed| directory.verify_special(SLOT_RESOURCES, sealed));
    result.embedded_blobs = embedded_blobs(signature);
    result
}

/// The requirements and entitlements blobs against their slots in the best CodeDirectory.
fn embedded_blobs(signature: &CodeSignature) -> Option<bool> {
    let directory = signature.best_code_directory()?;
    let blobs = [
        (SLOT_REQUIREMENTS, signature.requirements.as_deref()),
        (
            SLOT_ENTITLEMENTS,
            signature
                .entitlements
                .as_ref()
                .map(|entitlements| entitlements.blob.as_slice()),
        ),
        (SLOT_DER_ENTITLEMENTS, signature.der_entitlements.as_deref()),
    ];
    // A sealed slot whose blob is missing fails too (the blob was stripped after signing).
    let outcomes: Vec<bool> = blobs
        .iter()
        .filter_map(|(slot, bytes)| match bytes {
            Some(bytes) => directory.verify_special(*slot, bytes),
            None => directory
                .special_slot(*slot)
                .filter(|stored| stored.iter().any(|byte| *byte != 0))
                .map(|_| false),
        })
        .collect();
    (!outcomes.is_empty()).then(|| outcomes.iter().all(|matches| *matches))
}
