//! Framework API levels: which classes, methods and fields Android deprecated or removed, and in
//! which API level, from the SDK's `api-versions.xml` (the data Android lint uses), generated
//! into `generated/api_levels.rs` by `tools/generate_api_levels.py`.
//!
//! A reference in app code names the class it was compiled against, which may be an app class
//! inheriting the member (`Lcom/example/MainActivity;->getFragmentManager()...` for
//! `Activity.getFragmentManager`). [`resolve`] follows the app's own superclasses to the
//! framework class, then the framework's superclasses, to the class that declares the member.

use std::collections::{HashMap, HashSet};

use super::generated::api_levels::{FRAMEWORK_API_CHANGES, FRAMEWORK_SUPERCLASSES};

/// Superclass chains followed at most this far (the framework's deepest is under 15).
const MAX_HIERARCHY_DEPTH: usize = 64;

/// The app's own classes: each one's superclass, and the members they define (DEX notation,
/// `Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V`), so a member an app class defines
/// itself is never taken for the framework's.
#[derive(Debug, Clone, Default)]
pub struct AppClasses {
    /// Class to superclass.
    pub superclasses: HashMap<String, String>,
    /// Members the app's classes define.
    pub members: HashSet<String>,
}

/// When Android deprecated or removed an API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApiChange {
    /// API level that deprecated it.
    pub deprecated_in: Option<u16>,
    /// API level that removed it from the public SDK.
    pub removed_in: Option<u16>,
}

/// A framework member or class, as `api-versions.xml` describes it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FrameworkApi {
    /// DEX notation of what is affected: the member (`Landroid/view/Window;->setStatusBarColor(I)V`)
    /// or, when the whole class is deprecated, the class (`Landroid/os/AsyncTask;`).
    pub signature: String,
    /// When.
    pub change: ApiChange,
}

/// The change recorded for an exact signature (class, method or field in DEX notation).
pub fn change_of(signature: &str) -> Option<ApiChange> {
    let index = FRAMEWORK_API_CHANGES
        .binary_search_by(|(candidate, _, _)| (*candidate).cmp(signature))
        .ok()?;
    let (_, deprecated, removed) = FRAMEWORK_API_CHANGES[index];
    Some(ApiChange {
        deprecated_in: (deprecated > 0).then_some(deprecated),
        removed_in: (removed > 0).then_some(removed),
    })
}

/// The framework superclass of a framework class.
pub fn framework_superclass(class: &str) -> Option<&'static str> {
    let index = FRAMEWORK_SUPERCLASSES
        .binary_search_by(|(candidate, _)| (*candidate).cmp(class))
        .ok()?;
    Some(FRAMEWORK_SUPERCLASSES[index].1)
}

/// The deprecated or removed framework API a reference reaches, if any. `class` is the class
/// the reference names; `member` is `->name(params)return` for a method, `->name` for a field,
/// or empty for a type reference. A member reached through an app class resolves to the
/// framework class that declares it, unless an app class on the way defines it. A member of a
/// deprecated class counts as deprecated with it.
pub fn resolve(class: &str, member: &str, app: &AppClasses) -> Option<FrameworkApi> {
    let mut current = class;
    for _ in 0..MAX_HIERARCHY_DEPTH {
        // The app's own class: the member is the app's if this class defines it, else keep
        // climbing to the first framework class.
        if let Some(superclass) = app.superclasses.get(current) {
            if !member.is_empty() && app.members.contains(&format!("{current}{member}")) {
                return None;
            }
            current = superclass;
            continue;
        }
        if !member.is_empty() {
            let signature = format!("{current}{member}");
            if let Some(change) = change_of(&signature) {
                return Some(FrameworkApi { signature, change });
            }
        }
        if let Some(change) = change_of(current).filter(|change| change.deprecated_in.is_some()) {
            return Some(FrameworkApi {
                signature: current.to_owned(),
                change,
            });
        }
        // Types are checked on the class itself only; members also on its superclasses.
        if member.is_empty() {
            return None;
        }
        current = framework_superclass(current)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_resolve_through_app_and_framework_classes() {
        let none = AppClasses::default();
        let status_bar =
            resolve("Landroid/view/Window;", "->setStatusBarColor(I)V", &none).unwrap();
        assert_eq!(status_bar.change.deprecated_in, Some(35));
        // Activity.getFragmentManager is deprecated in API 28; reached through an app subclass
        // of Activity, and through a framework subclass (NativeActivity).
        let app = AppClasses {
            superclasses: HashMap::from([(
                "Lcom/example/Main;".to_owned(),
                "Landroid/app/Activity;".to_owned(),
            )]),
            members: HashSet::from([
                "Lcom/example/Main;->onCreate(Landroid/os/Bundle;)V".to_owned()
            ]),
        };
        let member = "->getFragmentManager()Landroid/app/FragmentManager;";
        for class in ["Lcom/example/Main;", "Landroid/app/NativeActivity;"] {
            let api = resolve(class, member, &app).unwrap();
            assert_eq!(api.signature, format!("Landroid/app/Activity;{member}"));
            assert_eq!(api.change.deprecated_in, Some(28));
        }
        // A deprecated class: its type and its members.
        assert_eq!(
            resolve("Landroid/os/AsyncTask;", "", &none)
                .unwrap()
                .change
                .deprecated_in,
            Some(30)
        );
        assert!(resolve("Landroid/os/AsyncTask;", "->cancel(Z)Z", &none).is_some());
        // Not deprecated, and app classes outside the framework.
        assert!(
            resolve(
                "Landroid/view/Window;",
                "->getDecorView()Landroid/view/View;",
                &none
            )
            .is_none()
        );
        assert!(resolve("Lcom/example/Other;", "->run()V", &none).is_none());
        // A member the app class defines itself is the app's.
        assert!(
            resolve(
                "Lcom/example/Main;",
                "->onCreate(Landroid/os/Bundle;)V",
                &app
            )
            .is_none()
        );
    }
}
