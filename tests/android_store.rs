//! Google Play store-readiness checks, on aapt2-built fixtures (`store.apk` decodes
//! `foregroundServiceType` flags for real) and on manifests changed one fact at a time.

use std::io::Cursor;

use msec::android::Apk;
use msec::android::analysis::store_checks::{FormFactor, play_target_requirement};
use msec::android::analysis::{StoreFinding, StoreRule};
use msec::android::manifest::{UsesFeature, UsesPermission};
use msec::archive::{Limits, ZipArchive};

const STORE_APK: &[u8] = include_bytes!("fixtures/android/store.apk");
const BASIC_APK: &[u8] = include_bytes!("fixtures/android/basic.apk");
const NATIVE_APK: &[u8] = include_bytes!("fixtures/android/native/native.apk");
const TODAY: &str = "2026-10-13";

fn read(bytes: &[u8]) -> Apk {
    Apk::read(&mut ZipArchive::open(Cursor::new(bytes.to_vec()), Limits::default()).unwrap())
}

fn summary(findings: &[StoreFinding]) -> Vec<(&'static str, Option<&str>, &str)> {
    findings
        .iter()
        .map(|finding| {
            (
                finding.rule.key(),
                finding.subject.as_deref(),
                finding.detail.as_str(),
            )
        })
        .collect()
}

#[test]
fn store_fixture_findings() {
    let apk = read(STORE_APK);
    let services = &apk
        .manifest
        .as_ref()
        .unwrap()
        .application
        .as_ref()
        .unwrap()
        .components;
    assert_eq!(services[0].foreground_service_type, Some(0xc0));
    assert_eq!(services[1].foreground_service_type, None);
    assert_eq!(
        summary(&apk.store_findings(TODAY)),
        [
            (
                "msec_store_target_sdk_below_play",
                None,
                "targets API 34; since 2026-08-31, Google Play requires API 36 for new apps and \
                 updates on phones and tablets (an extension to 2026-11-01 can be requested); \
                 below API 35, the published app is also hidden from new users on newer Android \
                 versions",
            ),
            (
                "msec_store_version_code_out_of_range",
                None,
                "android:versionCode 2100000001 is above 2100000000",
            ),
            (
                "msec_store_restricted_permission",
                Some("android.permission.QUERY_ALL_PACKAGES"),
                "Package visibility (QUERY_ALL_PACKAGES): Play Console declaration and an \
                 eligible core use",
            ),
            (
                "msec_store_restricted_permission",
                Some("android.permission.READ_SMS"),
                "SMS and Call Log permissions: Play Console declaration and an eligible core use",
            ),
            (
                "msec_store_restricted_permission",
                Some("android.permission.READ_MEDIA_IMAGES"),
                "Photo and video permissions: Play Console declaration and an eligible core use",
            ),
            (
                "msec_store_restricted_permission",
                Some("android.permission.health.READ_STEPS"),
                "Health Connect permissions: Play Console declaration and an eligible core use",
            ),
            (
                "msec_store_restricted_permission",
                Some("dev.appchk.fixture.store.HelperService"),
                "Accessibility API: a service bound with \
                 android.permission.BIND_ACCESSIBILITY_SERVICE needs a Play Console declaration",
            ),
            (
                "msec_store_fgs_permission_missing",
                Some("dev.appchk.fixture.store.CaptureService"),
                "type microphone needs android.permission.FOREGROUND_SERVICE_MICROPHONE, which is \
                 not requested",
            ),
        ]
    );
}

/// basic.apk: com.example package, API 35 (meets the 2025 requirement, not the 2026 one).
#[test]
fn basic_fixture_findings_follow_the_date() {
    let apk = read(BASIC_APK);
    let keys = |today| -> Vec<&'static str> {
        apk.store_findings(today)
            .iter()
            .map(|finding| finding.rule.key())
            .collect()
    };
    assert_eq!(
        keys(TODAY),
        [
            "msec_store_target_sdk_below_play",
            "msec_store_example_package"
        ]
    );
    // Before the 2026 requirement, API 35 met the 2025 one.
    assert_eq!(keys("2026-08-30"), ["msec_store_example_package"]);
    // Before any requirement in the table, there is nothing to compare with.
    assert_eq!(keys("2024-01-01"), ["msec_store_example_package"]);
    // After the extension window, no extension is offered.
    let late = apk.store_findings("2026-12-01");
    assert!(!late[0].detail.contains("extension"), "{}", late[0].detail);
}

#[test]
fn form_factors_have_their_own_requirements() {
    let mut apk = read(BASIC_APK);
    let manifest = apk.manifest.as_mut().unwrap();
    manifest.features.push(UsesFeature {
        name: Some("android.hardware.type.watch".to_owned()),
        required: true,
        gl_es_version: None,
    });
    assert_eq!(FormFactor::of(manifest), FormFactor::Wear);
    // Wear OS needs API 35 since 2026-08-31: basic's target meets it.
    assert!(
        apk.store_findings(TODAY)
            .iter()
            .all(|finding| finding.rule != StoreRule::TargetSdkBelowPlayRequirement)
    );
    let requirement = play_target_requirement(TODAY).unwrap();
    assert_eq!(requirement.new_and_updates(FormFactor::Tv), 34);
    assert_eq!(requirement.new_and_updates(FormFactor::Automotive), 35);
    assert_eq!(requirement.existing(FormFactor::PhoneTablet), Some(35));
}

#[test]
fn version_code_limits() {
    let mut apk = read(BASIC_APK);
    let details = |apk: &Apk| -> Vec<String> {
        apk.store_findings(TODAY)
            .into_iter()
            .filter(|finding| finding.rule == StoreRule::VersionCodeOutOfRange)
            .map(|finding| finding.detail)
            .collect()
    };
    assert!(details(&apk).is_empty());
    apk.manifest.as_mut().unwrap().version_code = Some(2_100_000_000);
    assert!(details(&apk).is_empty());
    apk.manifest.as_mut().unwrap().version_code = Some(0);
    assert_eq!(details(&apk), ["android:versionCode is 0"]);
    apk.manifest.as_mut().unwrap().version_code = None;
    assert_eq!(details(&apk), ["no android:versionCode"]);
}

#[test]
fn restricted_permissions_respect_their_target_level() {
    let mut apk = read(BASIC_APK);
    let manifest = apk.manifest.as_mut().unwrap();
    manifest.uses_permissions.push(UsesPermission {
        name: "android.permission.QUERY_ALL_PACKAGES".to_owned(),
        max_sdk: None,
        sdk_23_and_later: false,
        never_for_location: false,
    });
    let restricted = |apk: &Apk| {
        apk.store_findings(TODAY)
            .iter()
            .filter(|finding| finding.rule == StoreRule::RestrictedPermission)
            .count()
    };
    assert_eq!(restricted(&apk), 1);
    // QUERY_ALL_PACKAGES only exists for apps targeting API 30 and later.
    apk.manifest.as_mut().unwrap().target_sdk_version =
        Some(msec::android::manifest::SdkLevel::Api(29));
    assert_eq!(restricted(&apk), 0);
}

#[test]
fn untyped_foreground_services_are_found_from_api_34() {
    let mut apk = read(STORE_APK);
    let application = apk.manifest.as_mut().unwrap().application.as_mut().unwrap();
    for component in &mut application.components {
        component.foreground_service_type = None;
    }
    let fgs = |apk: &Apk| -> Vec<(&'static str, String)> {
        apk.store_findings(TODAY)
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.rule,
                    StoreRule::ForegroundServiceTypeMissing
                        | StoreRule::ForegroundServicePermissionMissing
                )
            })
            .map(|finding| (finding.rule.key(), finding.detail))
            .collect()
    };
    assert_eq!(
        fgs(&apk),
        [(
            "msec_store_fgs_type_missing",
            "requests android.permission.FOREGROUND_SERVICE, but none of its 3 services declares \
             android:foregroundServiceType"
                .to_owned()
        )]
    );
    apk.manifest.as_mut().unwrap().target_sdk_version =
        Some(msec::android::manifest::SdkLevel::Api(33));
    assert!(fgs(&apk).is_empty());
}

/// native.apk ships libpartial.so for armeabi-v7a only, next to arm64-v8a libraries.
#[test]
fn native_libraries_need_64_bit_builds() {
    let apk = read(NATIVE_APK);
    let findings: Vec<_> = apk
        .store_findings(TODAY)
        .into_iter()
        .filter(|finding| finding.rule == StoreRule::Missing64BitNativeCode)
        .collect();
    assert_eq!(
        summary(&findings),
        [(
            "msec_store_missing_64bit_code",
            Some("arm64-v8a"),
            "lib/arm64-v8a has no build of libpartial.so"
        )]
    );
}

/// Findings about one service name the permission concerned, so each stays distinct.
#[test]
fn service_findings_name_their_permission() {
    let apk = read(STORE_APK);
    let permissions: Vec<(StoreRule, Option<String>)> = apk
        .store_findings(TODAY)
        .into_iter()
        .filter(|finding| {
            finding
                .subject
                .as_deref()
                .is_some_and(|subject| subject.ends_with("Service"))
        })
        .map(|finding| (finding.rule, finding.permission))
        .collect();
    assert_eq!(
        permissions,
        [
            (
                StoreRule::RestrictedPermission,
                Some("android.permission.BIND_ACCESSIBILITY_SERVICE".to_owned())
            ),
            (
                StoreRule::ForegroundServicePermissionMissing,
                Some("android.permission.FOREGROUND_SERVICE_MICROPHONE".to_owned())
            ),
        ]
    );
}
