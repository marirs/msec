//! What msec's iOS checks could not examine in a particular app (ADR-0005's distinction in
//! APPCHK: a limitation is a check msec does not have; this is a check msec has that could not
//! run on some part of this app). A rule fed by an unchecked part is incomplete, not clean.
//!
//! Five causes exist:
//! - the App Store encrypted an executable (FairPlay, `cryptid` set): its code pages cannot be
//!   hashed, and the `__TEXT` sections msec reads (Objective-C method names, C strings) are
//!   ciphertext. Load commands, imports and the code signature stay readable;
//! - a code signature or certificate uses an algorithm or key type msec does not verify: the
//!   signer was neither confirmed nor refuted;
//! - `Info.plist` does not record what a check reads (`DTSDKName`, `MinimumOSVersion` for the
//!   upload requirements);
//! - the `Info.plist` a check reads could not be read (purpose strings of a bundle whose code
//!   uses a protected resource);
//! - the distribution method is not established ([`super::distribution`]), so a check whose
//!   verdict depends on it reaches none: `get-task-allow` (expected in a development build,
//!   not in a distribution one), and the certificate against the method when a profile is
//!   present but cannot be trusted.
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
    /// The file concerned: the executable, or `Info.plist` for what it does not record.
    pub location: String,
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
    /// App Store Connect's upload requirements (the SDK and the minimum iOS version).
    UploadRequirements,
    /// Purpose strings for the protected resources a bundle's code uses.
    PurposeStrings,
    /// Whether `get-task-allow`, which the main executable sets, is expected (a development
    /// build) or a finding (a distribution build).
    DebuggableBuild,
    /// The signing certificate against the distribution method.
    CertificateDistribution,
}

impl UncheckedCheck {
    /// The engine keys of the findings this check would have produced: rules mapping them are
    /// incomplete. Strings feed the secret and tracker scans, whose results carry their own
    /// unread files, so they name no key here.
    pub fn keys(self) -> Vec<&'static str> {
        match self {
            Self::PageHashes => vec![BinaryRule::SignatureMismatch.key()],
            Self::MethodNames => vec![
                AppRule::RequiredReasonUndeclared.key(),
                AppRule::PurposeStringMissing.key(),
            ],
            Self::Strings => Vec::new(),
            Self::SignerSignature => vec![
                BinaryRule::CmsSignatureInvalid.key(),
                BinaryRule::SignerNotApple.key(),
                BinaryRule::TeamMismatch.key(),
                AppRule::ProfileCertificateMismatch.key(),
                AppRule::CertificateDistributionMismatch.key(),
            ],
            Self::CertificateChain => vec![BinaryRule::SignerNotApple.key()],
            Self::UploadRequirements => vec![
                AppRule::UploadRequirementUnmet.key(),
                AppRule::UploadRequirementUpcoming.key(),
            ],
            Self::PurposeStrings => vec![AppRule::PurposeStringMissing.key()],
            Self::DebuggableBuild => vec![BinaryRule::GetTaskAllow.key()],
            Self::CertificateDistribution => vec![AppRule::CertificateDistributionMismatch.key()],
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
    /// The app does not record what the check reads.
    NotRecorded,
    /// The property list the check reads could not be read.
    PropertyListUnreadable,
    /// The distribution method is not established.
    DistributionUnknown,
}

/// Everything msec's checks could not examine in `app`: by executable, then slice, then
/// what `Info.plist` does not record.
pub fn unchecked(app: &AppBundle) -> Vec<Unchecked> {
    let mut found = Vec::new();
    for binary in &app.binaries {
        encrypted_parts(binary, &mut found);
        unverified_signers(binary, &mut found);
    }
    unrecorded_build(app, &mut found);
    unread_purpose_strings(app, &mut found);
    unknown_distribution(app, &mut found);
    found
}

/// Checks that need the distribution method, when it is not established: `get-task-allow`
/// whenever the main executable sets it; the certificate when a profile is present but cannot
/// be trusted (without one, as in App Store downloads, there is no intended method to compare
/// with, and the certificate check does not apply).
fn unknown_distribution(app: &AppBundle, found: &mut Vec<Unchecked>) {
    let super::distribution::Distribution::Unknown {
        reason,
        profile_present,
    } = super::distribution::of(app)
    else {
        return;
    };
    let Some(main) = app.binaries.first() else {
        return;
    };
    if super::analysis::debuggable(main) {
        found.push(Unchecked {
            check: UncheckedCheck::DebuggableBuild,
            cause: UncheckedCause::DistributionUnknown,
            location: main.path.clone(),
            architecture: None,
            detail: format!(
                "get-task-allow is true, and whether this is a development build (where it is \
                 expected) is not established: {reason}"
            ),
        });
    }
    let signed_with_certificate = main
        .signatures
        .first()
        .and_then(|check| check.signer.as_ref())
        .is_some_and(|signer| signer.signature.is_ok());
    if profile_present && signed_with_certificate {
        found.push(Unchecked {
            check: UncheckedCheck::CertificateDistribution,
            cause: UncheckedCause::DistributionUnknown,
            location: app
                .provisioning_profile
                .clone()
                .unwrap_or_else(|| main.path.clone()),
            architecture: None,
            detail: format!(
                "the signing certificate was not compared with the distribution method: {reason}"
            ),
        });
    }
}

/// Bundles whose code uses a protected resource but whose `Info.plist`, or one of whose
/// `InfoPlist.strings`, was not read: those purpose strings were not checked.
fn unread_purpose_strings(app: &AppBundle, found: &mut Vec<Unchecked>) {
    let mut reported: Vec<&str> = Vec::new();
    for binary in &app.binaries {
        let uses_resources = !binary.protected_resource_uses.is_empty()
            || binary
                .entitlements()
                .and_then(|plist| plist.as_ref().ok())
                .and_then(|plist| plist.root.as_dictionary())
                .is_some_and(|entitlements| {
                    !super::purpose_strings::entitlement_uses(entitlements).is_empty()
                });
        if !uses_resources {
            continue;
        }
        let (directory, info) = super::analysis::purpose_bundle(app, &binary.path);
        if reported.contains(&directory) {
            continue;
        }
        reported.push(directory);
        let user = binary
            .path
            .strip_prefix(app.path.as_str())
            .unwrap_or(&binary.path);
        if info.is_none() {
            found.push(Unchecked {
                check: UncheckedCheck::PurposeStrings,
                cause: UncheckedCause::PropertyListUnreadable,
                location: format!("{directory}Info.plist"),
                architecture: None,
                detail: format!(
                    "{user} uses protected resources, but this Info.plist was not read: its \
                     purpose strings were not checked"
                ),
            });
        }
        for localized in app
            .localized_info
            .iter()
            .filter(|localized| localized.bundle == directory)
        {
            if let Err(why) = &localized.strings {
                found.push(Unchecked {
                    check: UncheckedCheck::PurposeStrings,
                    cause: UncheckedCause::PropertyListUnreadable,
                    location: localized.path.clone(),
                    architecture: None,
                    detail: format!(
                        "{user} uses protected resources, but the {} localization was not \
                         read ({why}): its purpose strings were not checked",
                        localized.language
                    ),
                });
            }
        }
    }
}

/// The upload requirements need the SDK and minimum iOS version Xcode writes into
/// `Info.plist`. The day does not matter for whether they can be checked.
fn unrecorded_build(app: &AppBundle, found: &mut Vec<Unchecked>) {
    let Some(info) = &app.info else {
        return;
    };
    if let Err(missing) = super::upload_requirements::upload_problems(info, "") {
        found.push(Unchecked {
            check: UncheckedCheck::UploadRequirements,
            cause: UncheckedCause::NotRecorded,
            location: format!("{}Info.plist", app.path),
            architecture: None,
            detail: format!(
                "Info.plist does not record {}, which Xcode writes: App Store Connect's upload \
                 requirements were not checked",
                missing.keys.join(" or ")
            ),
        });
    }
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
                location: binary.path.clone(),
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
            location: binary.path.clone(),
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
                location: binary.path.clone(),
                architecture,
                detail: format!(
                    "the CMS signature was not verified ({problem}): who signed the code, its \
                     team and its certificate's fit with the profile were not checked"
                ),
            }),
            Ok(()) if signer.anchor_unverified() => found.push(Unchecked {
                check: UncheckedCheck::CertificateChain,
                cause: UncheckedCause::UnsupportedAlgorithm,
                location: binary.path.clone(),
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
