//! How a build is meant to be distributed, as far as the package establishes it: from the
//! embedded provisioning profile, trusted only when its CMS signature verifies over its
//! content (the chain to Apple is not checked, as for every profile msec reads).
//!
//! Development builds are expected to differ from distribution builds: they carry
//! `get-task-allow` (so a debugger can attach) and are signed with a development certificate.
//! Checks whose verdict depends on that ask here first, and a build whose method is not
//! established gets no verdict from them rather than a guess. App Store downloads carry no
//! profile (Apple re-signs them), so for them the method is not recorded in the package.

use super::AppBundle;
use super::profile::ProfileKind;

/// The distribution method of a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Distribution {
    /// Established by the embedded provisioning profile, whose signature verifies.
    Established {
        /// The method.
        kind: ProfileKind,
        /// The profile's path in the archive.
        profile: String,
    },
    /// Not established, with why (no profile, an unreadable one, one whose signature does not
    /// verify).
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

/// The app's distribution method.
pub fn of(app: &AppBundle) -> Distribution {
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
    if let Err(problem) = &profile.signature.verified {
        // The code signer's wording names each verification problem in words.
        let problem = crate::macho::signer::SignerProblem::Verify(problem.clone());
        return Distribution::Unknown {
            reason: format!(
                "the provisioning profile's signature does not verify ({problem}), so the \
                 distribution method it states cannot be trusted"
            ),
            profile_present: true,
        };
    }
    Distribution::Established {
        kind: profile.kind(),
        profile: path.clone(),
    }
}
