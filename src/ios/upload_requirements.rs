//! What App Store Connect requires of an uploaded iOS build: the SDK it was built with and the
//! lowest iOS version it may target, by the date each requirement takes effect. A build that
//! misses a requirement in force is refused at upload; one that misses an announced
//! requirement will be refused once it takes effect.
//!
//! Sources, read on 2026-10-21:
//! - <https://developer.apple.com/news/upcoming-requirements/>: since 2026-04-28, apps are
//!   built with Xcode 26 or later and the iOS 26 SDK; since 2026-09-09, iOS and iPadOS apps
//!   target iOS 13 or later;
//! - <https://developer.apple.com/ios/submit/> and
//!   <https://developer.apple.com/news/?id=k1mtkt1k>: from April 2027, the iOS 27 SDK and
//!   iOS 15 or later. Apple has not given the day; msec takes the first of the month.
//!
//! Apple publishes no list of upload error codes. Developers report the SDK requirement as
//! ITMS-90725 and the minimum version as error 90068 ("MinimumOSVersion ... not acceptable");
//! msec names the requirement, not the code. The table must follow Apple's announcements: a
//! requirement Apple adds later is not known to this build.

use super::BundleInfo;

/// One requirement, from the day it takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadRequirement {
    /// The day it takes effect (`yyyy-MM-dd`).
    pub effective: &'static str,
    /// Apple gave that day; when false, only the month is known and `effective` is its first.
    pub exact_day: bool,
    /// The oldest iOS SDK a build may use (`(26, 0)`).
    pub minimum_sdk: Option<(u32, u32)>,
    /// The lowest `MinimumOSVersion` a build may declare.
    pub minimum_os: Option<(u32, u32)>,
    /// Where Apple announced it.
    pub source: &'static str,
}

/// Apple's requirements, oldest first.
pub const REQUIREMENTS: [UploadRequirement; 3] = [
    UploadRequirement {
        effective: "2026-04-28",
        exact_day: true,
        minimum_sdk: Some((26, 0)),
        minimum_os: None,
        source: "https://developer.apple.com/news/upcoming-requirements/",
    },
    UploadRequirement {
        effective: "2026-09-09",
        exact_day: true,
        minimum_sdk: None,
        minimum_os: Some((13, 0)),
        source: "https://developer.apple.com/news/upcoming-requirements/",
    },
    UploadRequirement {
        effective: "2027-04-01",
        exact_day: false,
        minimum_sdk: Some((27, 0)),
        minimum_os: Some((15, 0)),
        source: "https://developer.apple.com/ios/submit/",
    },
];

/// What a requirement constrains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Constraint {
    /// The SDK the build was made with (`DTSDKName`).
    Sdk,
    /// The lowest iOS version the build targets (`MinimumOSVersion`).
    MinimumOs,
}

impl Constraint {
    /// The `Info.plist` key it is read from.
    pub fn key(self) -> &'static str {
        match self {
            Self::Sdk => "DTSDKName",
            Self::MinimumOs => "MinimumOSVersion",
        }
    }
}

/// A requirement the build does not meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadProblem {
    /// What it constrains.
    pub constraint: Constraint,
    /// The requirement is in force on the scan's day; otherwise it is announced.
    pub in_force: bool,
    /// The requirement.
    pub requirement: UploadRequirement,
    /// What the build has (`25.2`).
    pub found: (u32, u32),
    /// What it needs.
    pub required: (u32, u32),
}

impl std::fmt::Display for UploadProblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (found, required) = (version(self.found), version(self.required));
        let what = match self.constraint {
            Constraint::Sdk => format!(
                "built with the iOS {found} SDK; App Store Connect requires the iOS {required} \
                 SDK or later (Xcode {} or later)",
                self.required.0
            ),
            Constraint::MinimumOs => format!(
                "targets iOS {found} (MinimumOSVersion); App Store Connect requires iOS \
                 {required} or later"
            ),
        };
        let when = match (self.in_force, self.requirement.exact_day) {
            (true, true) => format!("since {}", self.requirement.effective),
            (true, false) => format!("since {}", month(self.requirement.effective)),
            (false, true) => format!("from {}", self.requirement.effective),
            (false, false) => format!(
                "from {} (Apple has not given the day)",
                month(self.requirement.effective)
            ),
        };
        write!(formatter, "{what} {when}")
    }
}

fn version((major, minor): (u32, u32)) -> String {
    format!("{major}.{minor}")
}

/// `2027-04-01` as `April 2027`.
fn month(date: &str) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let name = date
        .get(5..7)
        .and_then(|number| number.parse::<usize>().ok())
        .and_then(|number| MONTHS.get(number.wrapping_sub(1)));
    match (name, date.get(..4)) {
        (Some(name), Some(year)) => format!("{name} {year}"),
        _ => date.to_owned(),
    }
}

/// Why the requirements could not be checked: the keys that are missing or unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotRecorded {
    /// `DTSDKName`, `MinimumOSVersion`.
    pub keys: Vec<&'static str>,
}

/// The requirements a device build (`DTPlatformName` `iphoneos`, or absent) does not meet on
/// `today` (`yyyy-MM-dd`): each constraint against the strictest requirement in force, then
/// against each announced one stricter than that. Builds for another platform (the
/// simulator) cannot be uploaded at all and are not checked here.
pub fn upload_problems(info: &BundleInfo, today: &str) -> Result<Vec<UploadProblem>, NotRecorded> {
    if info
        .platform_name
        .as_deref()
        .is_some_and(|platform| platform != "iphoneos")
    {
        return Ok(Vec::new());
    }
    let sdk = info.sdk_name.as_deref().and_then(sdk_version);
    let minimum_os = info.minimum_os_version.as_deref().and_then(parse_version);
    let mut missing = Vec::new();
    if sdk.is_none() {
        missing.push(Constraint::Sdk.key());
    }
    if minimum_os.is_none() {
        missing.push(Constraint::MinimumOs.key());
    }
    if !missing.is_empty() {
        return Err(NotRecorded { keys: missing });
    }
    let mut problems = Vec::new();
    for (constraint, found) in [
        (Constraint::Sdk, sdk.unwrap_or_default()),
        (Constraint::MinimumOs, minimum_os.unwrap_or_default()),
    ] {
        let required_of = |requirement: &UploadRequirement| match constraint {
            Constraint::Sdk => requirement.minimum_sdk,
            Constraint::MinimumOs => requirement.minimum_os,
        };
        let strictest_in_force = REQUIREMENTS
            .iter()
            .filter(|requirement| requirement.effective <= today)
            .filter_map(|requirement| Some((required_of(requirement)?, requirement)))
            .max_by_key(|(required, _)| *required);
        let mut bar = (0, 0);
        if let Some((required, requirement)) = strictest_in_force {
            bar = required;
            if found < required {
                problems.push(UploadProblem {
                    constraint,
                    in_force: true,
                    requirement: *requirement,
                    found,
                    required,
                });
            }
        }
        for requirement in REQUIREMENTS
            .iter()
            .filter(|requirement| requirement.effective > today)
        {
            if let Some(required) = required_of(requirement)
                && required > bar
                && found < required
            {
                problems.push(UploadProblem {
                    constraint,
                    in_force: false,
                    requirement: *requirement,
                    found,
                    required,
                });
            }
        }
    }
    Ok(problems)
}

/// `iphoneos26.0` as `(26, 0)`.
fn sdk_version(name: &str) -> Option<(u32, u32)> {
    parse_version(name.strip_prefix("iphoneos")?)
}

/// `13.0`, `15`, `17.2.1` as `(major, minor)`.
fn parse_version(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = match parts.next() {
        Some(part) => part.parse().ok()?,
        None => 0,
    };
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(sdk: Option<&str>, minimum: Option<&str>) -> BundleInfo {
        let mut dictionary = crate::plist::Dictionary::default();
        if let Some(sdk) = sdk {
            dictionary.insert_first(
                "DTSDKName".to_owned(),
                crate::plist::Value::String(sdk.to_owned()),
            );
        }
        if let Some(minimum) = minimum {
            dictionary.insert_first(
                "MinimumOSVersion".to_owned(),
                crate::plist::Value::String(minimum.to_owned()),
            );
        }
        BundleInfo::of(&dictionary)
    }

    fn summary(problems: &[UploadProblem]) -> Vec<(Constraint, bool, (u32, u32))> {
        problems
            .iter()
            .map(|problem| (problem.constraint, problem.in_force, problem.required))
            .collect()
    }

    #[test]
    fn requirements_by_the_day_they_take_effect() {
        let old = info(Some("iphoneos25.2"), Some("12.0"));
        // Before the SDK requirement: nothing in force; both announced ones are not met.
        assert_eq!(
            summary(&upload_problems(&old, "2026-04-27").unwrap()),
            [
                (Constraint::Sdk, false, (26, 0)),
                (Constraint::Sdk, false, (27, 0)),
                (Constraint::MinimumOs, false, (13, 0)),
                (Constraint::MinimumOs, false, (15, 0)),
            ]
        );
        assert_eq!(
            summary(&upload_problems(&old, "2026-10-21").unwrap()),
            [
                (Constraint::Sdk, true, (26, 0)),
                (Constraint::Sdk, false, (27, 0)),
                (Constraint::MinimumOs, true, (13, 0)),
                (Constraint::MinimumOs, false, (15, 0)),
            ]
        );
        assert_eq!(
            summary(&upload_problems(&old, "2027-04-01").unwrap()),
            [
                (Constraint::Sdk, true, (27, 0)),
                (Constraint::MinimumOs, true, (15, 0)),
            ]
        );
        let current = info(Some("iphoneos26.1"), Some("15.0"));
        assert_eq!(
            summary(&upload_problems(&current, "2026-10-21").unwrap()),
            [(Constraint::Sdk, false, (27, 0))]
        );
        let next = info(Some("iphoneos27.0"), Some("16"));
        assert!(upload_problems(&next, "2027-06-01").unwrap().is_empty());
    }

    #[test]
    fn missing_keys_are_not_recorded_and_simulator_builds_are_not_checked() {
        assert_eq!(
            upload_problems(&info(None, Some("15.0")), "2026-10-21"),
            Err(NotRecorded {
                keys: vec!["DTSDKName"]
            })
        );
        assert_eq!(
            upload_problems(&info(Some("iphoneos26.0"), Some("fifteen")), "2026-10-21"),
            Err(NotRecorded {
                keys: vec!["MinimumOSVersion"]
            })
        );
        let mut simulator = info(Some("iphonesimulator25.0"), Some("12.0"));
        simulator.platform_name = Some("iphonesimulator".to_owned());
        assert!(
            upload_problems(&simulator, "2026-10-21")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn problems_say_what_and_when() {
        let problems =
            upload_problems(&info(Some("iphoneos25.2"), Some("12.0")), "2026-10-21").unwrap();
        let texts: Vec<String> = problems.iter().map(ToString::to_string).collect();
        assert_eq!(
            texts,
            [
                "built with the iOS 25.2 SDK; App Store Connect requires the iOS 26.0 SDK or \
                 later (Xcode 26 or later) since 2026-04-28",
                "built with the iOS 25.2 SDK; App Store Connect requires the iOS 27.0 SDK or \
                 later (Xcode 27 or later) from April 2027 (Apple has not given the day)",
                "targets iOS 12.0 (MinimumOSVersion); App Store Connect requires iOS 13.0 or \
                 later since 2026-09-09",
                "targets iOS 12.0 (MinimumOSVersion); App Store Connect requires iOS 15.0 or \
                 later from April 2027 (Apple has not given the day)",
            ]
        );
    }
}
