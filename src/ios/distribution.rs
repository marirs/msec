//! How a build is meant to be distributed, as far as the package establishes it: from the
//! embedded provisioning profile, believed only when Apple issued it
//! ([`ProfileSignature::trusted`](super::profile::ProfileSignature::trusted)): its signature
//! verifies, its signer's chain verifies to one of Apple's roots, and the signer is Apple's
//! provisioning-profile signing certificate. A signature that merely verifies proves the
//! profile is unchanged since signing, not who signed it: a self-signed profile, or one signed
//! with a developer's own certificate, could otherwise claim to be a development profile.
//!
//! Development builds are expected to differ from distribution builds: they carry
//! `get-task-allow` (so a debugger can attach) and are signed with a development certificate.
//! Checks whose verdict depends on that ask here first, and a build whose method is not
//! established gets no verdict from them rather than a guess. App Store downloads carry no
//! profile (Apple re-signs them), so for them the method is not recorded in the package.

use super::AppBundle;
use super::profile::{ProfileKind, ProfileTrust};

/// The distribution method of a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Distribution {
    /// Established by the embedded provisioning profile, which the trusted issuer (Apple)
    /// signed.
    Established {
        /// The method.
        kind: ProfileKind,
        /// The profile's path in the archive.
        profile: String,
    },
    /// Not established, with why (no profile, an unreadable one, one the trusted issuer did
    /// not sign).
    Unknown {
        /// Why, in words.
        reason: String,
        /// The app has an embedded profile (one that could not be trusted).
        profile_present: bool,
    },
}

impl Distribution {
    /// The method, when established.
    pub fn kind(&self) -> Option<ProfileKind> {
        match self {
            Self::Established { kind, .. } => Some(*kind),
            Self::Unknown { .. } => None,
        }
    }
}

/// The app's distribution method, believing only a profile Apple issued.
pub fn of(app: &AppBundle) -> Distribution {
    of_trusting(app, &ProfileTrust::APPLE)
}

/// The app's distribution method, believing only a profile `trust`'s issuer signed (tests use
/// their own test CA; every caller judging real apps uses [`of`]).
pub fn of_trusting(app: &AppBundle, trust: &ProfileTrust<'_>) -> Distribution {
    let (Some(path), Some(profile)) = (&app.provisioning_profile, &app.profile) else {
        return Distribution::Unknown {
            reason: "the app has no embedded.mobileprovision, which records the distribution \
                     method (App Store downloads carry none, nor do builds re-signed without \
                     one)"
                .to_owned(),
            profile_present: false,
        };
    };
    let profile = match profile {
        Ok(profile) => profile,
        Err(error) => {
            return Distribution::Unknown {
                reason: format!("the provisioning profile could not be read ({error})"),
                profile_present: true,
            };
        }
    };
    if let Err(problem) = profile.signature.trusted(trust) {
        return Distribution::Unknown {
            reason: format!(
                "the provisioning profile is not Apple's: {problem}; the distribution method \
                 it states cannot be believed"
            ),
            profile_present: true,
        };
    }
    Distribution::Established {
        kind: profile.kind(),
        profile: path.clone(),
    }
}
