//! Framework permissions: protection levels and labels, generated from AOSP
//! (`tools/generate_android_data.py`).

use super::generated::permissions::FRAMEWORK_PERMISSIONS;

/// How a permission is granted to an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantType {
    /// Runtime permission: the user is asked (`dangerous`).
    Runtime,
    /// Special app access the user turns on in Settings (`appop` flag), such as drawing over
    /// other apps or all-files access.
    SpecialAccess,
    /// Granted at install without asking (`normal`).
    InstallTime,
    /// Reserved for system, privileged or same-signer apps; an ordinary app requesting it is
    /// not granted it.
    System,
}

impl GrantType {
    /// Human-readable name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Runtime => "Runtime",
            Self::SpecialAccess => "Special access",
            Self::InstallTime => "Install-time",
            Self::System => "System only",
        }
    }
}

/// A framework permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameworkPermission {
    /// Full name.
    pub name: &'static str,
    /// `protectionLevel` as declared (`dangerous|instant`).
    pub protection_level: &'static str,
    /// What Android shows users (`take pictures and videos`).
    pub label: Option<&'static str>,
}

impl FrameworkPermission {
    /// How the permission is granted.
    pub fn grant_type(&self) -> GrantType {
        let mut parts = self.protection_level.split('|');
        let base = parts.next().unwrap_or("normal");
        let app_op = parts.any(|flag| flag == "appop");
        match base {
            "dangerous" => GrantType::Runtime,
            _ if app_op => GrantType::SpecialAccess,
            "normal" => GrantType::InstallTime,
            _ => GrantType::System,
        }
    }
}

/// Looks up a framework permission by full name.
pub fn framework_permission(name: &str) -> Option<FrameworkPermission> {
    FRAMEWORK_PERMISSIONS
        .binary_search_by_key(&name, |(permission, _, _)| permission)
        .ok()
        .map(|index| {
            let (name, protection_level, label) = FRAMEWORK_PERMISSIONS[index];
            FrameworkPermission {
                name,
                protection_level,
                label,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_for_binary_search() {
        assert!(
            FRAMEWORK_PERMISSIONS
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
        );
    }

    #[test]
    fn grant_types_follow_protection_levels() {
        let grant = |name| framework_permission(name).map(|permission| permission.grant_type());
        assert_eq!(grant("android.permission.CAMERA"), Some(GrantType::Runtime));
        assert_eq!(
            grant("android.permission.INTERNET"),
            Some(GrantType::InstallTime)
        );
        assert_eq!(
            grant("android.permission.SYSTEM_ALERT_WINDOW"),
            Some(GrantType::SpecialAccess)
        );
        assert_eq!(
            grant("android.permission.MANAGE_EXTERNAL_STORAGE"),
            Some(GrantType::SpecialAccess)
        );
        assert_eq!(
            grant("android.permission.INSTALL_PACKAGES"),
            Some(GrantType::System)
        );
        assert_eq!(grant("com.example.CUSTOM"), None);
        assert_eq!(
            framework_permission("android.permission.CAMERA")
                .unwrap()
                .label,
            Some("take pictures and videos")
        );
    }
}
