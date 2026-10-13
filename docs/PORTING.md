# Porting plan

msec ports the analysis core of MobSF v4.5.3 to Rust. The detailed inventory of what exists
upstream (modules, rules, data files, report keys, network calls, quirks) is in
[mobsf-inventory.md](mobsf-inventory.md).

## Principles

1. **Faithful by default.** Same checks, same rule data, same report keys. Each module names the
   upstream file it ports.
2. **Clear upstream bugs are fixed, never silently.** Every deviation is listed below with a test.
3. **Offline by default.** Every upstream network call (App Links, Play Store, App Store, Firebase
   probes, tracker and Maltrail refreshes, DNS) becomes an explicit opt-in. Database refreshes are
   maintenance calls, never side effects of a scan, so scans are deterministic.
4. **No mutation of inputs.** Upstream renames files and rewrites plists during IPA analysis; msec
   reads only.
5. **External tools stay optional.** jadx (with a Java runtime) is needed for code rules on APKs,
   as upstream. Everything else MobSF shells out to (apktool, aapt2, baksmali, apksigner,
   class-dump, `strings`, `nm`, `objdump`) is replaced natively.
6. **Golden diffs.** Upstream MobSF v4.5.3 (Docker image, outside this repository) runs on a fixed
   corpus; its JSON reports are compared section by section with msec output.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Scan types, magic bytes, hashes | Done (0.0.1) |
| 0 | Safe archive reader (`msec::archive`) | Done |
| 0 | Report types matching MobSF JSON keys, regex compatibility layer (`regex` then `fancy-regex`), golden-diff harness | Next |
| 1 | AXML + ARSC decoder; manifest data and permission database; manifest analysis; network security config; certificate and signature analysis; ELF checks | Planned |
| 2 | libsast-compatible pattern engine on decompiled sources; strings, secrets, entropy; trackers (Exodus); SBOM; report assembly, suppression, scorecard | Planned |
| 3 | iOS: plist, ATS, permissions; Mach-O checks; Objective-C and Swift metadata; IPA binary rules; iOS source zips | Planned |
| 4 | Malware: domain lists, IP2Location reader, APKiD rules via yara-x, VirusTotal (opt-in) | Planned |
| 5 | XAPK, APKS, AAB, JAR, AAR, SO entry points; icons | Planned |
| 6 | Dynamic analysis: log and report parsers, adb and Frida, proxy and TLS tests, iOS paths | Planned |

## Data with its own terms

| Data | Terms | Plan |
|---|---|---|
| MobSF rule YAMLs and knowledge-base tables | GPL-3.0-only | Ported into msec (GPL-3.0-only) |
| APKiD YARA rules | GPL-3.0 or commercial | Compatible with msec's license; load from the APKiD project at build or run time |
| Exodus tracker database | Exodus Privacy terms | Explicit refresh call; snapshot shipped only if terms allow |
| Maltrail domain list | Maltrail Trails Community Data License 1.0 (restricts third-party products) | Not shipped; user downloads it explicitly |
| IP2Location LITE DB5 | IP2Location LITE license (attribution) | Not shipped; user supplies it |

## Upstream deviations

| # | Upstream behaviour | msec behaviour |
|---|---|---|
| 1 | Extracts packages to disk with Python's `zipfile` | Never extracts: entries are read by name into memory, so entry names cannot write anywhere (`msec::archive`) |
| 2 | No limits beyond the upload size | Archive size, entry count, central directory size, per-entry output, total output and compression ratio are bounded ([`Limits`](../src/archive/limits.rs)); declared sizes are never trusted |
| 3 | Duplicate entry names: the last one wins (`zipfile`) | The first one wins, as on Android, and `DuplicateName` is reported |
| 4 | Structural tricks pass silently (prepended data, fake encryption flag, local header mismatches, overlapping entries, hidden data, second end record in the comment) | Each is reported as an `Anomaly`, marked when Android itself rejects it; the package is still analysed |
| 5 | CRC and size of extracted data are checked by `zipfile` and fail the extraction | A mismatch is reported as an anomaly and the data is still returned for analysis |
