//! Android API levels and the releases they belong to.

/// The newest API level msec knows (Android SDK Platform 37 is the newest in its data).
pub const LATEST_API: u32 = 37;

/// An Android release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndroidRelease {
    /// API level.
    pub api: u32,
    /// Marketing version (`7.0`, `14`).
    pub version: &'static str,
    /// Dessert or internal codename, when there is a well-known one.
    pub codename: Option<&'static str>,
}

impl AndroidRelease {
    /// `Android 7.0 (Nougat)`.
    pub fn label(&self) -> String {
        match self.codename {
            Some(codename) => format!("Android {} ({codename})", self.version),
            None => format!("Android {}", self.version),
        }
    }
}

const RELEASES: &[(u32, &str, Option<&str>)] = &[
    (1, "1.0", None),
    (2, "1.1", None),
    (3, "1.5", Some("Cupcake")),
    (4, "1.6", Some("Donut")),
    (5, "2.0", Some("Eclair")),
    (6, "2.0.1", Some("Eclair")),
    (7, "2.1", Some("Eclair")),
    (8, "2.2", Some("Froyo")),
    (9, "2.3", Some("Gingerbread")),
    (10, "2.3.3", Some("Gingerbread")),
    (11, "3.0", Some("Honeycomb")),
    (12, "3.1", Some("Honeycomb")),
    (13, "3.2", Some("Honeycomb")),
    (14, "4.0", Some("Ice Cream Sandwich")),
    (15, "4.0.3", Some("Ice Cream Sandwich")),
    (16, "4.1", Some("Jelly Bean")),
    (17, "4.2", Some("Jelly Bean")),
    (18, "4.3", Some("Jelly Bean")),
    (19, "4.4", Some("KitKat")),
    (20, "4.4W", Some("KitKat Wear")),
    (21, "5.0", Some("Lollipop")),
    (22, "5.1", Some("Lollipop")),
    (23, "6.0", Some("Marshmallow")),
    (24, "7.0", Some("Nougat")),
    (25, "7.1", Some("Nougat")),
    (26, "8.0", Some("Oreo")),
    (27, "8.1", Some("Oreo")),
    (28, "9", Some("Pie")),
    (29, "10", Some("Q")),
    (30, "11", Some("R")),
    (31, "12", Some("S")),
    (32, "12L", Some("Sv2")),
    (33, "13", Some("Tiramisu")),
    (34, "14", Some("Upside Down Cake")),
    (35, "15", Some("Vanilla Ice Cream")),
    (36, "16", Some("Baklava")),
    (37, "17", None),
];

/// The release for an API level, when msec knows it.
pub fn release(api: u32) -> Option<AndroidRelease> {
    RELEASES
        .iter()
        .find(|(level, _, _)| *level == api)
        .map(|&(api, version, codename)| AndroidRelease {
            api,
            version,
            codename,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_level_up_to_the_latest_is_known() {
        for api in 1..=LATEST_API {
            assert!(release(api).is_some(), "API {api}");
        }
        assert_eq!(release(24).unwrap().label(), "Android 7.0 (Nougat)");
        assert_eq!(release(LATEST_API + 1), None);
    }
}
