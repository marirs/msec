//! Entry name checks. Names are only ever used for lookup and display, never as paths.

use super::anomaly::{AnomalyKind, NameIssue};

/// Anomalies for one raw entry name: encoding first (mirrors Android's UTF-8 and NUL rule),
/// then suspicious patterns.
pub(super) fn name_anomalies(raw_name: &[u8]) -> Vec<AnomalyKind> {
    let mut anomalies = Vec::new();
    let decoded = std::str::from_utf8(raw_name);
    if decoded.is_err() || raw_name.contains(&0) {
        anomalies.push(AnomalyKind::InvalidNameEncoding);
    }
    let name = String::from_utf8_lossy(raw_name);
    for issue in name_issues(&name) {
        anomalies.push(AnomalyKind::SuspiciousName(issue));
    }
    anomalies
}

fn name_issues(name: &str) -> Vec<NameIssue> {
    let mut issues = Vec::new();
    let bytes = name.as_bytes();
    let has_drive_letter = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if name.starts_with('/') || has_drive_letter {
        issues.push(NameIssue::AbsolutePath);
    }
    if name.split(['/', '\\']).any(|segment| segment == "..") {
        issues.push(NameIssue::ParentTraversal);
    }
    if name.contains('\\') {
        issues.push(NameIssue::Backslash);
    }
    // NUL is already covered by InvalidNameEncoding.
    if name.chars().any(|c| c.is_control() && c != '\0') {
        issues.push(NameIssue::ControlCharacter);
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_package_names_are_clean() {
        for name in [
            "AndroidManifest.xml",
            "classes2.dex",
            "res/raw/a..b.txt",
            "Payload/App.app/Info.plist",
        ] {
            assert!(name_anomalies(name.as_bytes()).is_empty(), "{name}");
        }
    }

    #[test]
    fn hostile_names_are_flagged() {
        assert!(name_issues("../../etc/passwd").contains(&NameIssue::ParentTraversal));
        assert!(name_issues("/etc/passwd").contains(&NameIssue::AbsolutePath));
        assert!(name_issues("C:\\Windows\\x").contains(&NameIssue::AbsolutePath));
        assert!(name_issues("a\\b").contains(&NameIssue::Backslash));
        assert!(name_issues("evil\u{1b}[2J.txt").contains(&NameIssue::ControlCharacter));
        assert_eq!(
            name_anomalies(b"bad\xff"),
            vec![AnomalyKind::InvalidNameEncoding]
        );
        assert!(name_anomalies(b"nul\0name").contains(&AnomalyKind::InvalidNameEncoding));
    }
}
