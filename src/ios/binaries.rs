//! The executables of an app bundle and of its components, read as Mach-O, with their code
//! signatures checked: every page hash (unless the App Store encrypted the image), the
//! requirements and entitlements slots, and the two slots that seal the bundle itself
//! (`Info.plist` and `_CodeSignature/CodeResources`), against the bundle's own files.
//!
//! What this does not check: the CMS signature's certificates, the resource seal's contents
//! (each file CodeResources lists), and nested code's own seals beyond its executable. A
//! signature whose hashes all match shows the binary and its sealed files are unchanged since
//! signing; it does not show who signed it.

use std::io::{Read, Seek};

use crate::archive::ZipArchive;
use crate::macho::signature::{
    CodeSignature, SLOT_DER_ENTITLEMENTS, SLOT_ENTITLEMENTS, SLOT_INFO_PLIST, SLOT_REQUIREMENTS,
    SLOT_RESOURCES,
};
use crate::macho::{MachFile, MachO, parse};
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
    /// The bundle's `Info.plist` matches its slot; `None` when the slot is empty or there is
    /// no such file.
    pub info_plist: Option<bool>,
    /// The bundle's `_CodeSignature/CodeResources` matches its slot; `None` likewise.
    pub resources: Option<bool>,
    /// The signature's own requirements and entitlements match their slots; `None` when none
    /// is sealed.
    pub embedded_blobs: Option<bool>,
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
    /// Signed with a certificate (a CMS signature is present; not verified yet).
    Certificate,
}

/// Reads one executable and checks each slice's signature against the bundle at `bundle`
/// (directory with a trailing slash).
pub(super) fn read_binary<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    path: &str,
    role: BinaryRole,
    bundle: &str,
) -> BundleBinary {
    let mut binary = BundleBinary {
        path: path.to_owned(),
        role,
        size: 0,
        macho: Err("not in the archive".to_owned()),
        signatures: Vec::new(),
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
    let file = match parse(&bytes) {
        Ok(file) => file,
        Err(error) => {
            binary.macho = Err(error.to_string());
            return binary;
        }
    };
    let info_plist = archive
        .read_by_name(&format!("{bundle}Info.plist"))
        .ok()
        .flatten();
    let resources = archive
        .read_by_name(&format!("{bundle}_CodeSignature/CodeResources"))
        .ok()
        .flatten();
    for slice in &file.slices {
        let Ok(image) = &slice.image else {
            continue;
        };
        let start = slice.offset as usize;
        let slice_bytes = &bytes[start..start + slice.size as usize];
        binary.signatures.push(check(
            slice.architecture(),
            image,
            slice_bytes,
            info_plist.as_deref(),
            resources.as_deref(),
        ));
    }
    binary.macho = Ok(file);
    binary
}

fn check(
    architecture: String,
    image: &MachO,
    bytes: &[u8],
    info_plist: Option<&[u8]>,
    resources: Option<&[u8]>,
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
        note: None,
    };
    let signature = match &image.signature {
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
    result.info_plist =
        info_plist.and_then(|bytes| directory.verify_special(SLOT_INFO_PLIST, bytes));
    result.resources = resources.and_then(|bytes| directory.verify_special(SLOT_RESOURCES, bytes));
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
