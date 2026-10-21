//! What msec's iOS checks could not examine in a particular app (ADR-0005's distinction in
//! APPCHK: a limitation is a check msec does not have; this is a check msec has that could not
//! run on some part of this app). A rule fed by an unchecked part is incomplete, not clean.
//!
//! Two causes exist:
//! - the App Store encrypted an executable (FairPlay, `cryptid` set): its code pages cannot be
//!   hashed, and the `__TEXT` sections msec reads (Objective-C method names, C strings) are
//!   ciphertext. Load commands, imports and the code signature stay readable;
//! - a code signature or certificate uses an algorithm or key type msec does not verify: the
//!   signer was neither confirmed nor refuted.
//!
//! The C strings of an encrypted executable feed the secret and tracker scans, which report
//! the executable through [`crate::package_strings::Visitor::encrypted`]; they are listed here
//! too so one call names everything an app's analysis missed.

use super::analysis::{AppRule, BinaryRule};
use super::{AppBundle, BundleBinary, SignatureKind};

/// One check that did not run in full on part of the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unchecked {
    /// What could not be checked.
    pub check: UncheckedCheck,
    /// Why.
    pub cause: UncheckedCause,
    /// The executable's path in the archive.
    pub binary: String,
    /// The slice, for universal executables.
    pub architecture: Option<String>,
    /// What was not checked and why, in words.
    pub detail: String,
}

/// A check msec has that could not run on part of an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UncheckedCheck {
    /// The code signature's page hashes (`msec_macho_signature_mismatch`).
    PageHashes,
    /// Objective-C method names, read for required-reason APIs called by selector.
    MethodNames,
    /// C strings, read by the secret and tracker scans.
    Strings,
    /// The CMS signature over the CodeDirectory, and every signer check that needs it.
    SignerSignature,
    /// The certificate chain's links up to Apple's root.
    CertificateChain,
}

impl UncheckedCheck {
    /// The engine keys of the findings this check would have produced: rules mapping them are
    /// incomplete. Strings feed the secret and tracker scans, whose results carry their own
    /// unread files, so they name no key here.
    pub fn keys(self) -> Vec<&'static str> {
        match self {
            Self::PageHashes => vec![BinaryRule::SignatureMismatch.key()],
            Self::MethodNames => vec![AppRule::RequiredReasonUndeclared.key()],
            Self::Strings => Vec::new(),
            Self::SignerSignature => vec![
                BinaryRule::CmsSignatureInvalid.key(),
                BinaryRule::SignerNotApple.key(),
                BinaryRule::TeamMismatch.key(),
                AppRule::ProfileCertificateMismatch.key(),
                AppRule::CertificateDistributionMismatch.key(),
            ],
            Self::CertificateChain => vec![BinaryRule::SignerNotApple.key()],
        }
    }
}

/// Why a check did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UncheckedCause {
    /// The App Store encrypted the executable (FairPlay).
    Encrypted,
    /// An algorithm or key type msec does not verify.
    UnsupportedAlgorithm,
}

/// Everything msec's checks could not examine in `app`, by executable, then slice.
pub fn unchecked(app: &AppBundle) -> Vec<Unchecked> {
    let mut found = Vec::new();
    for binary in &app.binaries {
        encrypted_parts(binary, &mut found);
        unverified_signers(binary, &mut found);
    }
    found
}

fn encrypted_parts(binary: &BundleBinary, found: &mut Vec<Unchecked>) {
    let several = binary.signatures.len() > 1;
    let encrypted_images: Vec<(Option<String>, bool)> = binary
        .images()
        .zip(&binary.signatures)
        .map(|(image, check)| {
            (
                several.then(|| check.architecture.clone()),
                image
                    .encryption
                    .is_some_and(|encryption| encryption.encrypted())
                    && matches!(
                        check.kind,
                        SignatureKind::AdHoc | SignatureKind::Certificate
                    )
                    && check.pages.is_none(),
            )
        })
        .collect();
    for (architecture, unhashed) in encrypted_images {
        if unhashed {
            found.push(Unchecked {
                check: UncheckedCheck::PageHashes,
                cause: UncheckedCause::Encrypted,
                binary: binary.path.clone(),
                architecture,
                detail: "the App Store encrypted the code pages: their hashes cannot be checked"
                    .to_owned(),
            });
        }
    }
    for section in &binary.encrypted_sections {
        let (check, what) = match section.as_str() {
            "__objc_methname" => (
                UncheckedCheck::MethodNames,
                "Objective-C method names (__objc_methname) are encrypted: required-reason APIs \
                 called by selector cannot be found",
            ),
            "__cstring" => (
                UncheckedCheck::Strings,
                "C strings (__cstring) are encrypted: secrets and tracker hosts in them cannot \
                 be found",
            ),
            // ENCRYPTABLE_SECTIONS lists only the two above.
            _ => continue,
        };
        found.push(Unchecked {
            check,
            cause: UncheckedCause::Encrypted,
            binary: binary.path.clone(),
            architecture: None,
            detail: what.to_owned(),
        });
    }
}

fn unverified_signers(binary: &BundleBinary, found: &mut Vec<Unchecked>) {
    let several = binary.signatures.len() > 1;
    for check in &binary.signatures {
        let Some(signer) = &check.signer else {
            continue;
        };
        let architecture = several.then(|| check.architecture.clone());
        match &signer.signature {
            Err(problem) if problem.unsupported() => found.push(Unchecked {
                check: UncheckedCheck::SignerSignature,
                cause: UncheckedCause::UnsupportedAlgorithm,
                binary: binary.path.clone(),
                architecture,
                detail: format!(
                    "the CMS signature was not verified ({problem}): who signed the code, its \
                     team and its certificate's fit with the profile were not checked"
                ),
            }),
            Ok(()) if signer.anchor_unverified() => found.push(Unchecked {
                check: UncheckedCheck::CertificateChain,
                cause: UncheckedCause::UnsupportedAlgorithm,
                binary: binary.path.clone(),
                architecture,
                detail: "the certificate chain ends at Apple's root, but a link uses an \
                         algorithm that was not verified: whether Apple issued the certificate \
                         was not established"
                    .to_owned(),
            }),
            _ => {}
        }
    }
}
