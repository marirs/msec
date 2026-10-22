//! Store-review leads on an app's code (msec origin): what a reviewer would ask about, not a
//! policy verdict. Each reads what the DEX files define or refer to; none establishes what the
//! app sells, whether it deletes accounts another way, or how much it does beyond a web page.
//!
//! - A third-party payment SDK with no Google Play billing library: Play requires its billing
//!   for in-app digital goods (Payments policy), not for physical goods or services.
//! - Account creation through a recognised SDK with no recognised deletion call: Play requires
//!   an in-app path to delete an account the app lets people create, and a web link (account
//!   deletion requirement, since December 2023).
//! - A launcher activity that loads a constant remote URL into a WebView, in an app with few
//!   classes of its own: Play's minimum functionality and webview spam policies, App Store
//!   guideline 4.2.

use std::collections::{BTreeSet, HashMap};

use super::code_checks::{CodeEvidence, CodeFinding, CodeRule};
use crate::android::dex::DexEntry;
use crate::android::manifest::Manifest;

/// Class descriptor prefixes of third-party payment SDKs, with the SDK's name.
const PAYMENT_SDKS: [(&str, &str); 8] = [
    ("Lcom/stripe/android/", "Stripe"),
    ("Lcom/braintreepayments/api/", "Braintree"),
    ("Lcom/paypal/android/", "PayPal"),
    ("Lcom/paypal/checkout/", "PayPal Checkout"),
    ("Lcom/razorpay/", "Razorpay"),
    ("Lcom/adyen/checkout/", "Adyen"),
    ("Lsqip/", "Square In-App Payments"),
    ("Lco/paystack/android/", "Paystack"),
];

/// Google Play's billing: the Play Billing Library, or the legacy in-app billing AIDL.
const PLAY_BILLING: [&str; 2] = [
    "Lcom/android/billingclient/",
    "Lcom/android/vending/billing/",
];

/// Calls that create an account, by SDK (a prefix of `class->member` in DEX notation).
const ACCOUNT_CREATION: [&str; 6] = [
    "Lcom/google/firebase/auth/FirebaseAuth;->createUserWithEmailAndPassword",
    "Lcom/amplifyframework/auth/AuthCategory;->signUp",
    "Lcom/amazonaws/mobileconnectors/cognitoidentityprovider/CognitoUserPool;->signUp",
    "Lcom/auth0/android/authentication/AuthenticationAPIClient;->createUser",
    "Lcom/auth0/android/authentication/AuthenticationAPIClient;->signUp",
    "Lio/appwrite/services/Account;->create(",
];

/// Calls that delete one, by SDK.
const ACCOUNT_DELETION: [&str; 4] = [
    "Lcom/google/firebase/auth/FirebaseUser;->delete",
    "Lcom/amplifyframework/auth/AuthCategory;->deleteUser",
    "Lcom/amazonaws/mobileconnectors/cognitoidentityprovider/CognitoUser;->deleteUser",
    "Landroid/accounts/AccountManager;->removeAccount",
];

/// `WebView.loadUrl(String)`: the URL is argument slot 1 (slot 0 is the WebView).
const LOAD_URL: &str = "Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";

/// Most classes of the app's own package a web wrapper is taken to have: a WebView shell needs
/// a handful (activity, client, resources), an app with its own features many more.
const WRAPPER_MAX_OWN_CLASSES: usize = 20;

/// The store leads on the app's DEX files; `direct` is every reference as written, by
/// signature, with its callers.
pub fn analyse_store_leads(
    dex_files: &[DexEntry],
    manifest: &Manifest,
    direct: &HashMap<String, BTreeSet<String>>,
) -> Vec<CodeFinding> {
    let classes: BTreeSet<&str> = dex_files
        .iter()
        .flat_map(|entry| &entry.container.files)
        .flat_map(|file| {
            file.classes
                .iter()
                .filter_map(|class| file.class_descriptor(class))
        })
        .collect();
    let mut findings = Vec::new();
    findings.extend(payment_without_billing(&classes, direct));
    findings.extend(creation_without_deletion(direct));
    findings.extend(web_wrapper(dex_files, manifest, &classes));
    findings
}

/// Whether a class the app defines, or a member it refers to, starts with `prefix`.
fn present(
    prefix: &str,
    classes: &BTreeSet<&str>,
    direct: &HashMap<String, BTreeSet<String>>,
) -> bool {
    classes.iter().any(|class| class.starts_with(prefix))
        || direct.keys().any(|api| api.starts_with(prefix))
}

fn payment_without_billing(
    classes: &BTreeSet<&str>,
    direct: &HashMap<String, BTreeSet<String>>,
) -> Option<CodeFinding> {
    if PLAY_BILLING
        .iter()
        .any(|prefix| present(prefix, classes, direct))
    {
        return None;
    }
    let sdks: Vec<&str> = PAYMENT_SDKS
        .iter()
        .filter(|(prefix, _)| present(prefix, classes, direct))
        .map(|(_, name)| *name)
        .collect();
    let first = PAYMENT_SDKS
        .iter()
        .find(|(prefix, _)| present(prefix, classes, direct))?;
    Some(lead(
        CodeRule::PaymentSdkWithoutPlayBilling,
        Some(first.0.trim_end_matches('/').to_owned()),
        BTreeSet::new(),
        format!(
            "ships {} and no Google Play billing library: in-app digital goods (subscriptions, \
             premium features, virtual items) must use Google Play's billing; physical goods and \
             services, and enrolled alternative billing, do not. What the app sells is not \
             established",
            sdks.join(", ")
        ),
    ))
}

fn creation_without_deletion(direct: &HashMap<String, BTreeSet<String>>) -> Option<CodeFinding> {
    if direct.keys().any(|api| {
        ACCOUNT_DELETION
            .iter()
            .any(|prefix| api.starts_with(prefix))
    }) {
        return None;
    }
    let (api, callers) = direct
        .iter()
        .filter(|(api, _)| {
            ACCOUNT_CREATION
                .iter()
                .any(|prefix| api.starts_with(prefix))
        })
        .min_by(|left, right| left.0.cmp(right.0))?;
    Some(lead(
        CodeRule::AccountDeletionNotSeen,
        Some(api.clone()),
        callers.clone(),
        "creates accounts, and no recognised account deletion call is seen: Google Play \
         requires an in-app path to delete an account and its data, and a web link to request \
         it (App Store guideline 5.1.1(v) likewise). Deletion done on a server, or through a web \
         page the app opens, is not seen"
            .to_owned(),
    ))
}

fn web_wrapper(
    dex_files: &[DexEntry],
    manifest: &Manifest,
    classes: &BTreeSet<&str>,
) -> Option<CodeFinding> {
    let launchers: Vec<String> = manifest
        .application
        .as_ref()?
        .components
        .iter()
        .filter(|component| component.is_launcher())
        .map(|component| {
            let class = component
                .target_activity
                .as_deref()
                .unwrap_or(&component.name);
            format!("L{};", class.replace('.', "/"))
        })
        .collect();
    let package = manifest.package.as_deref()?;
    let own_prefix = format!("L{}/", package.replace('.', "/"));
    let own_classes = classes
        .iter()
        .filter(|class| class.starts_with(&own_prefix))
        .count();
    if own_classes > WRAPPER_MAX_OWN_CLASSES {
        return None;
    }
    let urls = super::security_checks::string_arguments(dex_files, LOAD_URL, 1);
    let (url, callers) = urls.into_iter().find(|(url, callers)| {
        (url.starts_with("https://") || url.starts_with("http://"))
            && callers.iter().any(|caller| {
                launchers
                    .iter()
                    .any(|launcher| caller.starts_with(&format!("{launcher}->")))
            })
    })?;
    let mut finding = lead(
        CodeRule::WebWrapper,
        Some(LOAD_URL.to_owned()),
        callers,
        format!(
            "the launcher activity loads {url} into a WebView, and the app defines {own_classes} \
             classes of its own (at most {WRAPPER_MAX_OWN_CLASSES} taken as a wrapper): possibly \
             a repackaged website. Google Play's minimum functionality and webview spam policies \
             and App Store guideline 4.2 are judged by review; what the page offers is not \
             established"
        ),
    );
    finding.evidence = CodeEvidence::ConstantArgument;
    finding.argument = Some(url);
    Some(finding)
}

fn lead(
    rule: CodeRule,
    api: Option<String>,
    callers: BTreeSet<String>,
    detail: String,
) -> CodeFinding {
    CodeFinding {
        rule,
        api,
        caller_count: callers.len(),
        callers: callers
            .into_iter()
            .map(|method| super::code_checks::Caller {
                method,
                checks_version: false,
            })
            .collect(),
        version_checked_callers: 0,
        detail,
        evidence: CodeEvidence::Reference,
        argument: None,
    }
}
