//! Store-review leads on msec's store-lead fixtures (tests/fixtures/android/build_store_leads.sh):
//! the positive app (a website in a WebView launched first, Firebase sign-up without deletion,
//! Stripe without Play's billing) gives each lead once, as dexdump's disassembly shows the code
//! for; the clean app (native UI, Play's billing beside Stripe, sign-up with deletion) gives none;
//! a DEX file cut short is not read in full.

use std::io::Cursor;

use msec::android::Apk;
use msec::android::analysis::{CodeEvidence, CodeRule};
use msec::archive::{Limits, ZipArchive};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/android");

fn read(name: &str) -> Apk {
    let bytes = std::fs::read(format!("{FIXTURES}/{name}")).unwrap();
    let mut archive = ZipArchive::open(Cursor::new(bytes), Limits::default()).unwrap();
    Apk::read(&mut archive)
}

fn leads(apk: &Apk) -> Vec<(CodeRule, Option<String>, CodeEvidence, Option<String>)> {
    apk.code_findings()
        .into_iter()
        .filter(|finding| CodeRule::STORE_LEADS.contains(&finding.rule))
        .map(|finding| {
            (
                finding.rule,
                finding.api,
                finding.evidence,
                finding.argument,
            )
        })
        .collect()
}

#[test]
fn each_lead_once_on_the_positive_app() {
    let disassembly =
        std::fs::read_to_string(format!("{FIXTURES}/leads/positive.disassembly.txt")).unwrap();
    // What the code does, as dexdump reads it.
    assert!(disassembly.contains("const-string v0, \"https://shop.example.com/\""));
    assert!(disassembly.contains("Landroid/webkit/WebView;.loadUrl:(Ljava/lang/String;)V"));
    assert!(
        disassembly
            .contains("Lcom/google/firebase/auth/FirebaseAuth;.createUserWithEmailAndPassword")
    );
    assert!(!disassembly.contains("billingclient"));
    assert_eq!(
        leads(&read("leads.apk")),
        [
            (
                CodeRule::PaymentSdkWithoutPlayBilling,
                Some("Lcom/stripe/android".to_owned()),
                CodeEvidence::Reference,
                None
            ),
            (
                CodeRule::AccountDeletionNotSeen,
                Some(
                    "Lcom/google/firebase/auth/FirebaseAuth;->createUserWithEmailAndPassword(\
                     Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;"
                        .to_owned()
                ),
                CodeEvidence::Reference,
                None
            ),
            (
                CodeRule::WebWrapper,
                Some("Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V".to_owned()),
                CodeEvidence::ConstantArgument,
                Some("https://shop.example.com/".to_owned())
            ),
        ]
    );
}

#[test]
fn the_clean_app_gives_no_lead() {
    assert_eq!(leads(&read("leads-clean.apk")), []);
}

#[test]
fn a_dex_file_cut_short_is_not_read_in_full() {
    let apk = read("leads-incomplete.apk");
    assert!(apk.dex_files[0].container.error.is_none());
    assert!(apk.dex_files[1].container.error.is_some());
    // What was read is the clean code: no lead from it.
    assert_eq!(leads(&apk), []);
}
