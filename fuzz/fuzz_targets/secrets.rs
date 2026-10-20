//! The secret detectors on arbitrary text: MobSF's patterns with their look-around emulation,
//! gitleaks' rules with allowlists and the generic-rule filter, and MobSF's entropy heuristic;
//! and MobSF's URL extraction with msec's host parsing. Matches run on bytes, so they may split
//! multi-byte characters; nothing may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use msec::secrets::{detect, entropy_runs, is_secret_key};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = detect(&text, "assets/config.json");
    let _ = entropy_runs(&text);
    let _ = is_secret_key(&text);
    for url in msec::urls::urls(&text) {
        let _ = msec::urls::host_of(url);
    }
});
