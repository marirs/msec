# msec

Mobile app security analysis core for Android and iOS packages, in Rust.

msec is a port of the analysis engine of
[MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) to a
Rust library. It ports only the analysis core: package handling, manifest and plist analysis,
certificate and signature checks, network security configuration, binary hardening checks, code
rules, secrets, trackers and malware indicators. MobSF's web interface, REST API, database and
user management are not part of msec.

> **Status: early development.** Version 0.0.x contains the scan-input layer only. The API will
> change between releases until 0.1.0.

msec is an independent project. It is not affiliated with or endorsed by the MobSF project.

## What works today

```rust
use msec::{FileHashes, ScanType};

let bytes = std::fs::read("app.apk")?;
let scan_type = ScanType::detect("app.apk", &bytes)?;   // extension + magic-byte check
let hashes = FileHashes::of_bytes(&bytes);              // md5 (scan id), sha1, sha256
println!("{:?} on {:?}: {}", scan_type, scan_type.platform(), hashes.sha256);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Supported inputs (recognition and validation): APK, XAPK, APKS, AAB, JAR, AAR, SO, source ZIP,
IPA, DYLIB, A. APPX is recognised but not analysed.

## Roadmap

Ported in this order, each step checked against MobSF v4.5.3 reports on a fixed corpus:

1. Foundation: a safe archive reader (done), report types matching MobSF's JSON report keys, a
   rule-engine regex compatibility layer.
2. Android without a decompiler: binary XML and resource table decoding, manifest data and
   permissions (done), manifest analysis, network security config, certificate and signature
   analysis, ELF checks.
3. Code rules and strings: a libsast-compatible pattern engine over decompiled sources (jadx as an
   optional external tool), strings and secrets, trackers, SBOM, scorecard.
4. iOS: plist, ATS and permissions, Mach-O checks, Objective-C metadata, IPA binary rules.
5. Malware indicators: domain checks, APKiD rules via yara-x.
6. Remaining inputs (XAPK, APKS, AAB, JAR, AAR, SO), then dynamic analysis.

Network access is off by default; database refreshes are explicit calls.

## License

GPL-3.0-only, the same license as MobSF, from which msec is derived. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
