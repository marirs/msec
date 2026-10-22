//! Store-review leads on an app bundle (msec origin): what App Review would ask about, not its
//! verdict, except for private frameworks, which App Store Connect rejects. Each reads what the
//! executables link (load commands), import (classes) or name (selectors, C strings); none
//! establishes what the app sells, which login is primary, or whether accounts are deleted
//! another way.
//!
//! - A third-party payment SDK (an embedded framework or a linked library named like one) with
//!   nothing linking StoreKit: guideline 3.1.1 requires in-app purchase for digital goods, not
//!   for physical goods or services.
//! - A third-party login SDK (linked, or its sign-in class imported) with nothing importing
//!   Sign in with Apple's provider: guideline 4.8 requires an equivalent login option that
//!   limits data to name and email, keeps the email private and does not track; Sign in with
//!   Apple is one, others count, and some apps are exempt.
//! - Account creation selectors with no deletion selector: guideline 5.1.1(v).
//! - A library linked from /System/Library/PrivateFrameworks (guideline 2.5.1, ITMS-90338), or
//!   a C string naming one, as code loading it at run time would.

use super::AppBundle;
use super::analysis::{AppFinding, AppRule};

/// Where Apple's private frameworks live.
pub const PRIVATE_FRAMEWORKS: &str = "/System/Library/PrivateFrameworks/";

/// Framework or library name prefixes of third-party payment SDKs.
const PAYMENT_SDKS: [&str; 7] = [
    "Stripe",
    "Braintree",
    "PayPal",
    "Razorpay",
    "Adyen",
    "SquareInAppPaymentsSDK",
    "Paystack",
];

/// Framework or library names of third-party login SDKs, and their sign-in classes.
const LOGIN_SDKS: [&str; 6] = [
    "GoogleSignIn",
    "FBSDKLoginKit",
    "FacebookLogin",
    "MSAL",
    "LineSDK",
    "AppAuth",
];
const LOGIN_CLASSES: [&str; 3] = [
    "_OBJC_CLASS_$_GIDSignIn",
    "_OBJC_CLASS_$_FBSDKLoginManager",
    "_OBJC_CLASS_$_MSALPublicClientApplication",
];

/// Sign in with Apple's provider and button classes.
const SIGN_IN_WITH_APPLE: [&str; 2] = [
    "_OBJC_CLASS_$_ASAuthorizationAppleIDProvider",
    "_OBJC_CLASS_$_ASAuthorizationAppleIDButton",
];

/// Objective-C selectors that create accounts (Firebase Authentication, AWS Cognito).
const CREATION_SELECTORS: [&str; 2] = [
    "createUserWithEmail:password:completion:",
    "signUp:password:userAttributes:validationData:",
];
/// Selectors that delete them.
const DELETION_SELECTORS: [&str; 2] = ["deleteWithCompletion:", "deleteUser"];
/// Every selector `BundleBinary::account_selectors` keeps.
pub const ACCOUNT_SELECTORS: [&str; 4] = [
    CREATION_SELECTORS[0],
    CREATION_SELECTORS[1],
    DELETION_SELECTORS[0],
    DELETION_SELECTORS[1],
];

/// The store leads and private-framework checks on the app.
pub fn analyse_store_leads(app: &AppBundle) -> Vec<AppFinding> {
    let mut findings = Vec::new();
    findings.extend(payment_without_storekit(app));
    findings.extend(login_without_equivalent(app));
    findings.extend(creation_without_deletion(app));
    private_frameworks(app, &mut findings);
    findings
}

/// The last path component of a library (`@rpath/Stripe.framework/Stripe` is `Stripe`).
fn library_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Every library an executable links or the bundle carries, by name, each once.
fn libraries(app: &AppBundle) -> Vec<String> {
    let mut names: Vec<String> = app
        .binaries
        .iter()
        .flat_map(|binary| {
            binary
                .images()
                .flat_map(|image| image.dylibs.iter().map(|dylib| dylib.name.clone()))
                .chain(std::iter::once(binary.path.clone()))
                .collect::<Vec<String>>()
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn any_import(app: &AppBundle, symbols: &[&str]) -> bool {
    app.binaries
        .iter()
        .flat_map(|binary| binary.images())
        .any(|image| symbols.iter().any(|symbol| image.imports(symbol)))
}

fn payment_without_storekit(app: &AppBundle) -> Option<AppFinding> {
    let libraries = libraries(app);
    if libraries
        .iter()
        .any(|library| library.ends_with("/StoreKit.framework/StoreKit"))
    {
        return None;
    }
    let mut sdks: Vec<&str> = libraries
        .iter()
        .map(|library| library_name(library))
        .filter(|name| PAYMENT_SDKS.iter().any(|sdk| name.starts_with(sdk)))
        .collect();
    sdks.sort_unstable();
    sdks.dedup();
    let first = *sdks.first()?;
    Some(AppFinding {
        rule: AppRule::PaymentSdkWithoutStoreKit,
        location: format!("{}Info.plist", app.path),
        subject: Some(first.to_owned()),
        detail: format!(
            "carries {} and nothing links StoreKit: digital goods and features (subscriptions, \
             premium content, in-game currency) must use in-app purchase (guideline 3.1.1); \
             physical goods and services may use other payment. What the app sells is not \
             established",
            sdks.join(", ")
        ),
    })
}

fn login_without_equivalent(app: &AppBundle) -> Option<AppFinding> {
    if any_import(app, &SIGN_IN_WITH_APPLE) {
        return None;
    }
    let libraries = libraries(app);
    let mut sdks: Vec<&str> = libraries
        .iter()
        .map(|library| library_name(library))
        .filter(|name| LOGIN_SDKS.contains(name))
        .collect();
    if sdks.is_empty() && any_import(app, &LOGIN_CLASSES) {
        sdks.push("a third-party sign-in class");
    }
    sdks.sort_unstable();
    sdks.dedup();
    let first = *sdks.first()?;
    Some(AppFinding {
        rule: AppRule::ThirdPartyLoginWithoutEquivalent,
        location: format!("{}Info.plist", app.path),
        subject: Some(first.to_owned()),
        detail: format!(
            "uses {} and nothing uses Sign in with Apple (ASAuthorizationAppleIDProvider): if a \
             third-party login is the primary one, guideline 4.8 requires an equivalent option \
             that limits data to name and email, lets people keep their email private and does \
             not track them. Another such option, or an exemption (the company's own accounts, \
             education or enterprise accounts, government ID, a client for a specific \
             service), is not seen",
            sdks.join(", ")
        ),
    })
}

fn creation_without_deletion(app: &AppBundle) -> Option<AppFinding> {
    let selectors: Vec<&str> = app
        .binaries
        .iter()
        .flat_map(|binary| binary.account_selectors.iter().map(String::as_str))
        .collect();
    if selectors
        .iter()
        .any(|selector| DELETION_SELECTORS.contains(selector))
    {
        return None;
    }
    let (binary, selector) = app.binaries.iter().find_map(|binary| {
        binary
            .account_selectors
            .iter()
            .find(|selector| CREATION_SELECTORS.contains(&selector.as_str()))
            .map(|selector| (binary, selector))
    })?;
    Some(AppFinding {
        rule: AppRule::AccountDeletionNotSeen,
        location: binary.path.clone(),
        subject: Some(selector.clone()),
        detail: format!(
            "calls {selector} (creates an account) and no recognised deletion call \
             (deleteWithCompletion:, deleteUser) is seen: an app that lets people create an \
             account must let them delete it within the app (guideline 5.1.1(v)). Deletion done \
             on a server, or through a web page the app opens, is not seen"
        ),
    })
}

fn private_frameworks(app: &AppBundle, findings: &mut Vec<AppFinding>) {
    for binary in &app.binaries {
        let mut linked: Vec<&str> = binary
            .images()
            .flat_map(|image| &image.dylibs)
            .map(|dylib| dylib.name.as_str())
            .filter(|name| name.starts_with(PRIVATE_FRAMEWORKS))
            .collect();
        linked.sort_unstable();
        linked.dedup();
        for library in linked {
            findings.push(AppFinding {
                rule: AppRule::PrivateFrameworkLinked,
                location: binary.path.clone(),
                subject: Some(library.to_owned()),
                detail: format!(
                    "links {library}, a private framework: apps may use public APIs only, and \
                     App Store Connect rejects builds that use non-public ones (guideline 2.5.1, \
                     ITMS-90338)"
                ),
            });
        }
        for path in &binary.private_framework_strings {
            findings.push(AppFinding {
                rule: AppRule::PrivateFrameworkPath,
                location: binary.path.clone(),
                subject: Some(path.clone()),
                detail: format!(
                    "names {path}, as code that loads a private framework at run time (dlopen, \
                     NSBundle) would: whether it is loaded is not established. Private \
                     frameworks are non-public API (guideline 2.5.1, ITMS-90338)"
                ),
            });
        }
    }
}
