//! Components of an IPA: the frameworks and dynamic libraries in the app's `Frameworks/`
//! directory, named by their bundle and versioned by their `Info.plist`.

use super::{Component, ComponentInventory, ComponentKind, Confidence, Evidence, EvidenceSource};
use crate::ios::{ComponentKind as BundleKind, Ipa};

/// Components of the IPA's app bundle; none without one.
pub fn of_ipa(ipa: &Ipa) -> ComponentInventory {
    let Some(app) = &ipa.app else {
        return ComponentInventory::default();
    };
    let mut components: Vec<Component> = app
        .components
        .iter()
        .filter(|component| matches!(component.kind, BundleKind::Framework | BundleKind::Library))
        .map(|component| {
            let file = component
                .path
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or(&component.path);
            let name = file
                .strip_suffix(".framework")
                .or_else(|| file.strip_suffix(".dylib"))
                .unwrap_or(file)
                .to_owned();
            let info = component.info.as_ref();
            let version =
                info.and_then(|info| info.short_version.clone().or_else(|| info.version.clone()));
            let confidence = if version.is_some() {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let evidence_path = match component.kind {
                BundleKind::Framework => format!("{}Info.plist", component.path),
                _ => component.path.clone(),
            };
            Component {
                kind: ComponentKind::Framework,
                group: None,
                name,
                version,
                confidence,
                evidence: vec![Evidence {
                    source: EvidenceSource::FrameworkInfo,
                    path: evidence_path,
                }],
                sha256: None,
                direct: None,
                packaging: None,
                bundle_identifier: info.and_then(|info| info.identifier.clone()),
            }
        })
        .collect();
    components.sort_by(|left, right| left.name.cmp(&right.name));
    ComponentInventory {
        components,
        ..ComponentInventory::default()
    }
}
