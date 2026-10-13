# MobSF v4.5.3 analysis core: Rust porting inventory

- Source: `github.com/MobSF/Mobile-Security-Framework-MobSF`, tag `v4.5.3` (commit `d3869ad`), read from a shallow
  clone on 2026-10-13. Nothing was installed, imported or executed from the checkout.
- Scope: the analysis engine (static Android/iOS, malware analyzer, dynamic analyzer). Django UI, templates, auth,
  users, REST/view plumbing, DB models and static web assets are out of scope; places where core logic is tangled into
  views are flagged with **[TANGLED]**.
- Difficulty scale: **S** (< 1 dev-day, mechanical), **M** (days), **L** (1-3 weeks, real parsing work),
  **XL** (open-ended / needs an external engine).
- All LOC are Python-only `wc -l` counts (blank lines and comments included).

---

## A. Repository map (Python LOC)

Total Python: **39,804 LOC** in `mobsf/`. Frida JS shipped as data: 10,675 lines (118 files). Templates: ~31k lines (UX).

| Path | LOC | Class | Notes |
|---|---:|---|---|
| `mobsf/StaticAnalyzer/views/android/` (excl. `views/`, `db_interaction.py`) | 6,059 | **CORE** | APK/XAPK/APKS/AAB/JAR/AAR/SO/source-zip pipeline, manifest, cert, NSC, code analysis, strings, icons. Entry functions are Django views **[TANGLED]** |
| `mobsf/StaticAnalyzer/views/android/kb/` (in the above) | 1,312 | CORE data | `android_manifest_desc.py` (53 manifest rule templates), `dvm_permissions.py` (permission DB, LGPL header from androguard) |
| `mobsf/StaticAnalyzer/views/android/views/` | 366 | UX | source viewer, find, manifest view |
| `mobsf/StaticAnalyzer/views/ios/` (excl. `views/`, `db_interaction.py`) | 2,478 | **CORE** | IPA / iOS source zip / dylib; plist, ATS, Mach-O, classdump, binary rules |
| `mobsf/StaticAnalyzer/views/ios/views/` | 165 | UX | source viewer |
| `mobsf/StaticAnalyzer/views/common/binary/` | 884 | **CORE** | `elf.py`, `macho.py` (LIEF checksec), `lib_analysis.py`, `strings.py` |
| `mobsf/StaticAnalyzer/views/common/{a,entropy,firebase,secret_detection,shared_func}.py` + `views/sast_engine.py` + `tools/strings.py` | 1,420 | **CORE / SUPPORT** | `.a` analysis, entropy, Firebase checks, secret patterns, unzip/hash/URL+email regex, libsast wrapper. `shared_func.py` also holds two views (`compare_apps`, `scan_library`) **[TANGLED]** |
| `mobsf/StaticAnalyzer/views/common/{appsec,suppression}.py` + `android/db_interaction.py` + `ios/db_interaction.py` | 1,299 | CORE (report shaping) + DB | report dict assembly, scorecard, suppression filtering; all read/write Django models **[TANGLED]** |
| `mobsf/StaticAnalyzer/views/common/{pdf,async_task}.py`, `views/comparer.py`, `StaticAnalyzer/{models,forms,tests,admin}.py` | 2,020 | UX / OUT | PDF/JSON report view, django-q tasks, compare, ORM |
| `mobsf/StaticAnalyzer/views/windows/` | 772 | note only | APPX: manifest XML + binskim/binscope via Windows VM XML-RPC |
| `mobsf/StaticAnalyzer/tools/androguard4/` | 7,605 | **CORE (vendored)** | trimmed androguard 4 (`apk.py` 2,924, `axml.py` 3,709 = AXML+ARSC) + apkInspector (819); header says "Androguard4 APK - Nov 24, 2024 - 04a5703b8ba7c181bb9f5f5995a2c16b6f9353cf" |
| `mobsf/StaticAnalyzer/tools/*.jar`, `tools/ios/*` | binaries | external tools | apktool 3.0.3, baksmali 3.0.8, bundletool 1.17.2, apksigner, vd2svg 0.4.4; class-dump, class-dump-swift, jtool.ELF64, CgbiPngFix |
| `mobsf/MalwareAnalyzer/` | 1,173 | **CORE** | APKiD, malware permissions, behaviour rules, domain checks (maltrail, malwaredomainlist, IP2Location), Exodus trackers, VirusTotal |
| `mobsf/DynamicAnalyzer/` | 9,238 | CORE (dynamic, last) | Android (adb/Frida/mitmproxy) 2,982; common Frida 666; iOS Corellium + device 5,360; tools 224 |
| `mobsf/MobSF/utils.py` | 941 | SUPPORT (mixed) | regexes (URL/email/strings/Google keys), `update_local_db`, `upstream_proxy`, `find_java_binary`, `find_aapt`, `append_scan_status` (writes to DB **[TANGLED]**), `run_with_timeout`, adb helpers |
| `mobsf/MobSF/security.py` | 685 | SUPPORT | SSRF-safe HTTP (`safe_request`, `resolve_public_ip`, `valid_host`), path-traversal checks; plus exec-hash hooks (OUT) |
| `mobsf/MobSF/settings.py` | 542 | SUPPORT | feature flags, timeouts, external URLs, skip paths |
| `mobsf/MobSF/{init,tools_download,exceptions}.py` | 420 | SUPPORT | first-run bootstrap; downloads jadx 1.5.0 from GitHub |
| `mobsf/MobSF/views/**`, `urls.py`, `forms.py`, `wsgi.py`, `management/` | 3,573 | UX / OUT | REST API, auth, SAML, home/upload, APK downloader |
| `mobsf/install/windows/` | 624 | OUT | Windows VM setup for binskim |
| `mobsf/__main__.py` | 71 | OUT | |
| `mobsf/signatures/` | data | CORE data | exodus trackers, maltrail, malwaredomainlist, IP2Location LITE DB5 |
| `mobsf/templates/`, `mobsf/static/` | n/a | OUT | |

Rough core budget: Android static 6.1k + iOS static 2.5k + common 2.3k + report shaping 1.3k + malware 1.2k
≈ **13.3k LOC** to port, plus the **7.6k LOC** vendored androguard parser (replace with Rust AXML/ARSC/signing code),
plus **9.2k LOC** dynamic.

---

## B. Analyzers

### B.0 Cross-cutting engine facts

- **Orchestration is in view functions.** `static_analyzer()` (`StaticAnalyzer/views/android/static_analyzer.py`) and
  `static_analyzer_ios()` (`views/ios/static_analyzer.py`) take a Django `request`, look up the upload in
  `RecentScansDB`, then dispatch. The real pipelines are the `*_task` functions (`apk_analysis_task`,
  `src_analysis_task`, `ipa_analysis_task`, `ios_analysis_task`) and `common_analysis` / `so_analysis` /
  `dylib_analysis` / `a_analysis` (the last four are still views). **[TANGLED]**
- State is a mutable dict (`app_dic`) threaded through every step. `append_scan_status()` writes progress into the DB
  row; port as a progress callback / `tracing` events.
- Every step catches all exceptions and logs; the report is best-effort. Keep that: each Rust analyzer should return
  `Result` but the orchestrator should degrade to empty sections.
- **Code rules run on JADX-decompiled Java** (`<app_dir>/java_source/**/*.java`) for APK/XAPK/APKS/AAB/JAR/AAR, and
  on `.java` + `.kt` for Android source zips. **Smali is never scanned**: `dex_2_smali` runs baksmali in fire-and-forget
  daemon threads only so the UI can show smali. iOS rules run on `.m` (ObjC rules) and `.swift` (Swift rules) source
  only; IPA binaries get a separate Python rule table matched against class-dump output + symbols.
- Third-party paths are skipped by substring: `SKIP_CLASS_PATH = {com/google/, androidx, okhttp2/, okhttp3/,
  com/android/, com/squareup, okhttp/, android/content/, com/twitter/, twitter4j/, android/support/, org/apache/,
  oauth/signpost, android/arch, org/chromium/, com/facebook, org/spongycastle, org/bouncycastle, com/amazon/identity/,
  io/fabric/sdk, com/instabug, com/crashlytics/android, kotlinx/, kotlin/}` (`MobSF/settings.py`).
- Feature flags (`settings.py`, env `MOBSF_*`): `PERM_MAPPING_ENABLED=1`, `DEX2SMALI_ENABLED=1`,
  `SO_ANALYSIS_ENABLED=1`, `DYLIB_ANALYSIS_ENABLED=1`, `DOMAIN_MALWARE_SCAN=1`, `APKID_ENABLED=1`,
  `NIAP_ENABLED=''` (off), `CVSS_SCORE_ENABLED=''` (off, so `average_cvss` is `None`), `VT_ENABLED=''` (off).
  Timeouts: `JADX_TIMEOUT=1000`, `SAST_TIMEOUT=1000`, `BINARY_ANALYSIS_TIMEOUT=600` s. Zip limits: 400 MB per entry,
  3000 MB total uncompressed.
- **Regex dialect.** All rules are Python `re` patterns. Rust's `regex` crate lacks look-around and backreferences.
  Counted in the rule YAMLs: look-around in 4 patterns (2 in `android_rules.yaml`, 1 in `objective_c_rules.yaml`, 1 in
  `swift_rules.yaml`); no backreferences or atomic groups; 4 inline flag groups in `swift_rules.yaml`. The
  hard-coded regexes use look-around heavily: `secret_detection.py` (41 occurrences, boundary assertions) and
  `STRINGS_REGEX` in `utils.py`. Suggested approach: compile with `regex` first and fall back to `fancy-regex` per
  pattern. Also note Python's `\w`/`\b` are Unicode-aware for `str` patterns, and `re.findall` returns capture groups
  when the pattern has groups.

### B.1 Android static (APK, XAPK, APKS, AAB, JAR, AAR, SO, source ZIP)

#### Input routing (`views/android/static_analyzer.py::static_analyzer`, **[TANGLED]**)

| Input | Handler | What happens |
|---|---|---|
| `.apk` | `apk.py::apk_analysis` -> `apk_analysis_task` | full pipeline below |
| `.xapk` | `xapk.py::handle_xapk` | unzip, read `manifest.json`, take the `split_apks[id=='base'].file`, rename to `<md5>.apk`, then APK pipeline |
| `.apks` | `xapk.py::handle_split_apk` | unzip, take `*base.apk` or the first `*.apk` without `config.`, then APK pipeline |
| `.aab` | `xapk.py::handle_aab` | `java -jar bundletool-all-1.17.2.jar build-apks --bundle=X --output=X.apks --mode=universal` (300 s timeout), extract `universal.apk`, then APK pipeline |
| `.jar` / `.aar` | `jar_aar.py::common_analysis` (view) | unzip; AAR: manifest + manifest analysis + cert; ELF libs; trackers; jadx; code analysis; `obfuscated_check` (looks for `LocalVariableTable` bytes in `.class` files, adds synthetic `aar_class_obfuscation` finding); strings; firebase; domains. No APKiD, no Play Store |
| `.so` | `so.py::so_analysis` (view) | ELF checksec on the single lib; symbols go into `file_analysis`; strings/secrets/URLs; firebase; domains; trackers from domains |
| `.zip` | `apk.py::src_analysis` -> `valid_source_code` | detects Eclipse (`AndroidManifest.xml` + `src/`), Android Studio (`app/src/main/AndroidManifest.xml` + `java/` or `kotlin/`), one level of nesting, or iOS (`*.xcodeproj`, redirect to iOS analyzer) |

#### APK pipeline (`apk.py::apk_analysis_task`, in order)

| # | Step (file::function) | Computes | Report keys | External tools / libs | Network |
|---|---|---|---|---|---|
| 1 | `shared_func.py::hash_gen`, `utils.file_size` | SHA-1/SHA-256 (MD5 = upload id), size string `"N.NNMB"` | `md5`, `sha1`, `sha256`, `size` | hashlib | - |
| 2 | `shared_func.py::unzip` | safe extraction: skip encrypted entries, zip-slip check, reserved-name conflict (`AndroidManifest.xml`, `resources.arsc`, `META-INF/CERT.*`, `classes*.dex` prefixes -> `_conflict_/`), size caps, mode 0644; fallback to OS `unzip` | `files` (zip namelist) | zipfile, OS `unzip` | - |
| 3 | `app.py::androguard_parse` | vendored androguard `APK`: app name, icon path (max dpi), manifest AXML->XML bytes, `ARSCParser` | (feeds `app_name`, `icon_path`, strings) | `tools/androguard4` (lxml, asn1crypto, cryptography) | - |
| 4 | `app.py::aapt_parse` + `aapt.py::AndroidAAPT` | `aapt2 dump badging` (package, permissions, min/target SDK, label, icon, launchable activity, features), `aapt2 dump strings`, `aapt list` | fallback values only | aapt/aapt2 from PATH or Android SDK (optional; skipped if absent) | - |
| 5 | `cert_analysis.py::get_hardcoded_cert_keystore` | files by extension: `.cer .pem .cert .crt .pub .key .pfx .p12 .der` and `.jks .bks` | `file_analysis` | - | - |
| 6 | `manifest_utils.py::get_parsed_manifest` -> `get_manifest_file` | decoded manifest: runs `java -jar apktool_3.0.3.jar d --match-original --frame-path <tmp> --force --no-src <apk> --output apktool_out`; fallback androguard XML; then bs4 repair | (manifest DOM; `apktool_out/res/xml` used by NSC and icons) | apktool (Java), defusedxml minidom, bs4 | - |
| 7 | `manifest_utils.py::extract_manifest_data` | components, permissions (+`uses-permission-sdk-23`), SDK levels, version, main activity (first `MAIN` action, else `LAUNCHER` category, else aapt), icons; permission metadata from `DVM_PERMISSIONS` (strip to last dotted segment for `android.`/`com.google.` perms; else `SPECIAL_PERMISSIONS`; else `unknown`) | `package_name`, `main_activity`, `activities`, `services`, `receivers`, `providers`, `libraries`, `min_sdk`, `max_sdk`, `target_sdk`, `version_code`, `version_name`, (`permissions` via step 8) | - | - |
| 8 | `manifest_analysis.py::manifest_analysis` | rule engine in code (see C.3): min SDK, cleartext, debuggable, backup, testOnly, directBootAware, taskAffinity, launchMode, StrandHogg 1/2, exported components x permission protectionLevel matrix, implicit export via intent-filter, provider default export (<17), grant-uri-permission, secret dialer codes, SMS port, high intent/action priority; browsable activities; **App Links `assetlinks.json` fetch** | `manifest_analysis`, `exported_activities`, `exported_count`, `browsable_activities`, `permissions` | `kb/android_manifest_desc.py` | **Yes**: `GET https://<host>/.well-known/assetlinks.json` per BROWSABLE http(s) host (thread pool, SSRF-guarded `safe_request`) |
| 8b | `network_security.py::analysis` (called from 8) | parses `res/xml/<networkSecurityConfig>.xml` (from `apktool_out/res/xml` or `app/src/main/res/xml` for Studio; fallback any `*network_security*.xml`): base-config, domain-config, trust-anchors, pin-set, debug-overrides | `network_security` | defusedxml | - |
| 9 | `app.py::get_apk_name` | androguard label, aapt label, else `<string name="app_name">` regex in `res/values/*.xml` | `app_name` | - | - |
| 10 | `playstore.py::get_app_details` | reachability probe then `google_play_scraper.app(package)`; fallback AppMonsta API if `APPMONSTA_API` key set | `playstore_details` | google-play-scraper, bs4(lxml) | **Yes**: `https://play.google.com`, Play Store scrape, `api.appmonsta.com` |
| 11 | `MalwareAnalyzer/views/android/permissions.py::check_malware_permission` | intersect with 25 top-malware + 44 other-abused permissions | `malware_permissions` | - | - |
| 12 | `icon_analysis.py::get_icon_apk` | resolve icon (androguard/aapt name, guess from `res/`, vector XML -> SVG via `java -jar vd2svg-0.4.4.jar`, adaptive icon XML parsing, svgutils) and copy to downloads dir | `icon_path` | vd2svg (Java), svgutils, apktool res | - |
| 13 | `common/binary/lib_analysis.py::library_analysis(..,'elf')` -> `elf.py::ELFChecksec` | for every `*.so`: NX, PIE/DSO/REL, stack canary, RELRO (none/partial/full; N/A for Dart), RPATH, RUNPATH, `_chk` fortified functions, symbols stripped; strings; symtab symbols | `binary_analysis` (list), feeds strings | LIEF (`lief.parse`, `has_nx`, dynamic entries, `GNU_RELRO`, `symtab_symbols`), OS `nm --debug-syms`, OS `strings` | - |
| 14 | `cert_analysis.py::cert_info` | androguard: v1/v2/v3 certs + pubkeys (DER) -> subject, sig alg, validity, issuer, serial, hash alg, md5/sha1/sha256/sha512 of cert, pubkey alg/bits/fingerprint; scheme versions from `java -jar apksigner.jar verify --verbose` (regex `Verified using vN scheme ... true/false`), fallback androguard `is_signed_v1/v2/v3`; if androguard failed, `apksigtool` + `apksigcopier` path. Findings: signed/unsigned, Janus (v1 with minSdk<27 nuance), debug cert `CN=Android Debug`, SHA1withRSA (downgraded if `SHA-256-Digest` in `MANIFEST.MF`), MD5 | `certificate_analysis` | androguard4, asn1crypto, cryptography, apksigner.jar (Java), apksigtool/apksigcopier (fallback) | - |
| 15 | `MalwareAnalyzer/views/android/apkid.py::apkid_analysis` | APKiD scan of APK (recursive into nested zips, YARA timeout 30 s, wrapped in `BINARY_ANALYSIS_TIMEOUT`) | `apkid` | apkid (yara-python) | - |
| 16 | `MalwareAnalyzer/views/Trackers.py::Trackers.get_trackers` | class list per `*.dex` via `java -jar baksmali list classes`, match Exodus `code_signature` regexes | `trackers` | baksmali (Java), tldextract | **Yes**: Exodus DB refresh `GET https://reports.exodus-privacy.eu.org/api/trackers` on every scan when online (plus connectivity probe to google.com/baidu.com) |
| 17 | `converter.py::apk_2_java` | `jadx -ds java_source -q -r --show-bad-code <apk>`; on failure, per-DEX | (enables 19-20) | jadx 1.5.0 (downloaded at first run) | - (download at install) |
| 18 | `converter.py::dex_2_smali` | `java -jar baksmali-3.0.8-dev-fat.jar d <dex> -o smali_source/` in daemon threads | none (UI only) | baksmali | - |
| 19 | `code_analysis.py::code_analysis` | libsast `PatternMatcher` over `java_source` `.java/.kt` (one read, several rule sets): SBOM, `android_rules.yaml`, `android_apis.yaml`, permission mapping (only rules whose `id` is a requested permission), `behaviour_rules.yaml`, optional NIAP `ChoiceMatcher` (`.java` + manifest `.xml`); then URL/email regex extraction per file | `code_analysis`, `android_api`, `permission_mapping`, `behaviour`, `niap_analysis`, `sbom`, `urls`, `emails` | libsast, PyYAML | - |
| 19b | `sbom_analysis.py::sbom` | `*.version` files (`group_name.version` -> `group:name@ver`) + first-line `package x.y;` of every scanned file, merged by prefix | `sbom.sbom_versioned`, `sbom.sbom_packages` | - | - |
| 20 | `strings.py::get_strings_metadata` | resource strings via androguard ARSC (`"key" : "value"`), Firebase creds (`google_api_key` `AIza...`, `google_app_id`), key-name secret heuristic `is_secret_key`, known-format secrets, ELF strings per `.so` (secrets incl. entropy), code string literals (`STRINGS_REGEX`) + entropy secrets; URL/email extraction | `strings`, `secrets`, `urls`, `emails` (extended) | - | - |
| 21 | `common/firebase.py::firebase_analysis` | for each `*.firebaseio.com` URL: `GET https://<host>/.json` (open DB if 200); Remote Config: `POST https://firebaseremoteconfig.googleapis.com/v1/projects/<num>/namespaces/firebase:fetch?key=<api_key>` | `firebase_urls` | requests | **Yes** |
| 22 | `MalwareAnalyzer/views/MalwareDomainCheck.py::scan` | domains from `urls_list`; maltrail update; match malwaredomainlist CSV + maltrail set; DNS resolve (public IPs only) + IP2Location DB5 lookup + OFAC country list | `domains` | IP2Location, requests | **Yes**: maltrail download from GitHub, DNS per domain, connectivity probe |
| 23 | `db_interaction.py::save_get_ctx` | persist + build context; `suppression.py::process_suppression[_manifest]` wraps findings with summaries | all keys (see D.1) | Django ORM **[TANGLED]** | - |
| 24 | `apk.py::generate_dynamic_context` | `appsec.py::get_android_dashboard` scorecard, `get_avg_cvss`, dynamic flag, VirusTotal | `appsec`, `average_cvss`, `dynamic_analysis_done`, `virus_total` | requests | **Yes** if `VT_ENABLED`: VirusTotal v3 |

Source-zip pipeline (`src_analysis_task`): steps 5-11, `get_icon_from_src`, 19 (on `app/src/main/java|kotlin` or
`src/`), 20 (`.java`, `.kt`), 21, 22, trackers from domains only (`get_trackers_domains_or_deps`); no cert, no ELF,
no APKiD, no jadx.

#### Android module table

| Module | LOC | Key functions | Inputs | Difficulty | Suggested Rust approach |
|---|---:|---|---|---|---|
| `views/android/static_analyzer.py`, `apk.py`, `jar_aar.py`, `so.py`, `xapk.py` | 133+504+278+174+127 | routing, `apk_analysis_task`, `src_analysis_task`, `common_analysis`, `so_analysis`, `handle_xapk/split_apk/aab`, `valid_source_code`, `obfuscated_check` | upload path, md5 | M | one `AndroidScan` orchestrator struct with typed sub-results; input-type detection by magic + extension; XAPK/APKS are zip+JSON (S); AAB: keep bundletool as optional external tool, or analyze the AAB directly (base/manifest/AndroidManifest.xml is protobuf, not AXML; needs `prost` + aapt2 Resources.proto) (L) |
| `tools/androguard4/{apk,axml,types,util}.py`, `apkinspector/*` | 7,605 | `APK`, `AXMLPrinter`, `ARSCParser`, signature v1/v2/v3 parsing, tolerant ZIP (apkInspector) | APK bytes | **L** | write a Rust AXML + ARSC decoder (string pool, resource map, chunk walker, attribute value decoding, `@type/name` resolution incl. framework ids from `resources/public.xml`, 2,480 entries). Existing crates (`axmldecoder`, `abxml`) are small or unmaintained; a focused port is ~1.5-2k LOC Rust. Replaces both apktool and androguard for manifest/res xml. Tolerant ZIP reading (malformed local headers, as apkInspector does) matters for malware |
| `aapt.py`, `app.py` | 151+166 | `AndroidAAPT`, `androguard_parse`, `aapt_parse`, `get_apk_name` | APK | S | drop aapt; derive the same fields from the Rust AXML/ARSC decoder |
| `manifest_utils.py` | 330 | `get_manifest_file`, `get_xml_namespace`, `get_parsed_manifest`, `extract_manifest_data` | decoded XML | S | `roxmltree`/`quick-xml` on decoded manifest; keep namespace-prefix logic |
| `manifest_analysis.py` + `kb/android_manifest_desc.py` | 879+856 | `manifest_analysis`, `get_browsable_activities`, `assetlinks_check`, `_check_url` | manifest DOM, `man_data_dic` | M | encode the protectionLevel x export decision table explicitly (the Python repeats it 4 times); templates as a static table keyed by rule id; assetlinks check behind a `network` feature |
| `network_security.py` | 295 | `read_netsec_config`, `analysis` | NSC XML | S | straight port |
| `cert_analysis.py` | 507 | `get_hardcoded_cert_keystore`, `get_cert_details`, `get_pub_key_details`, `get_signature_versions`, `apksigtool_cert`, `get_cert_data`, `cert_info` | APK, META-INF | **M-L** | parse v1 PKCS#7 (`cms`, `x509-cert`, `der` from RustCrypto), APK Signing Block v2/v3/v3.1 (simple length-prefixed format) natively; replace `apksigner verify` with native verification or presence detection (decide parity: MobSF's flags mean "verified"); v4 needs a `.idsig` file (always false for uploads). Fingerprint formulas (RSA `n:e`, DSA `p:q:g:y`, EC curve name + DER tail) must be copied exactly |
| `code_analysis.py` + `views/sast_engine.py` | 201+118 | `code_analysis`, `get_perm_rules`, `permission_transform`, `SastEngine`, `ChoiceEngine.format_findings` | `java_source` dir | M | Rust `libsast`-equivalent (see C.0): file walker with extension/ignore filters, read-once cache, per-rule matchers, line-range formatting (`"3,4,5"` strings); rayon for parallelism |
| `converter.py` | 192 | `apk_2_java`, `dex_2_smali`, `run_apktool` | APK/DEX | S (wrapper) / XL (replacement) | keep jadx as a pluggable external decompiler (`Decompiler` trait); drop baksmali (UI only) and apktool (replaced by Rust AXML) |
| `sbom_analysis.py` | 78 | `sbom`, `android_sbom`, `extract_packages`, `merge_common_packages` | files | S | straight port |
| `strings.py` + `common/secret_detection.py` + `common/entropy.py` + parts of `common/shared_func.py` | 191+222+63+~150 | `get_strings_metadata`, `strings_from_apk/so/code`, `detect_known_secrets`, `get_secrets`, `sort_secrets`, `get_entropies`, `is_secret_key`, `strings_and_entropies`, `url_n_email_extract` | ARSC strings, ELF strings, source | S | straight port; use `fancy-regex` for the look-around patterns or hand-written boundary checks |
| `playstore.py` | 113 | `get_app_details`, `app_search` | package | M (fragile) | optional `network` feature; Play Store HTML/JS scraping changes often, consider dropping or isolating |
| `icon_analysis.py` | 428 | `get_icon_apk`, `get_icon_apk_res`, `get_icon_from_src`, `convert_vector_to_svg`, `get_icon_svg_from_xml`, `guess_icon_path` | res/ | M | low priority; return icon bytes/path; vector drawable -> SVG is a small converter (pathData is already SVG path syntax) |
| `common/binary/elf.py` + `lib_analysis.py` + `binary/strings.py` + `tools/strings.py` | 381+129+37+24 | `ELFChecksec.checksec/is_nx/is_pie/has_canary/relro/rpath/runpath/fortify/is_symbols_stripped/strings/get_symbols`, `library_analysis` | `*.so` | S-M | `goblin` or `object`: PT_GNU_STACK flags (NX), e_type + DT_DEBUG heuristic (PIE vs DSO), symbols `__stack_chk_fail`/`__intel_security_cookie`, PT_GNU_RELRO + DT_FLAGS BIND_NOW / DT_FLAGS_1 NOW, DT_RPATH/DT_RUNPATH, `*_chk` symbols, `.symtab` presence, Dart detection (`_kDartVmSnapshotInstructions`, `Dart_Cleanup`). Strings: implement natively; note MobSF prefers host `strings` output (min len 4) and falls back to a Python scanner (min len 6, results quoted) so output differs by host |
| `db_interaction.py`, `common/suppression.py`, `common/appsec.py` | 297+348+406 | `get_context_from_analysis`, `process_suppression`, `process_suppression_manifest`, `get_android_dashboard`, `common_fields` | analysis dicts | S | pure functions over a typed `Report`; suppression rules become an input struct instead of a DB query |

### B.2 iOS static (IPA, source ZIP, dylib, .a)

Routing: `views/ios/static_analyzer.py::static_analyzer_ios` (view) -> `ipa.py::ipa_analysis` / `ios_analysis`,
`dylib.py::dylib_analysis`, `common/a.py::a_analysis`. Source zips arrive via the Android `src_analysis` redirect.

#### IPA pipeline (`ipa.py::ipa_analysis_task`)

| # | Step (file::function) | Computes | Report keys | External tools / libs | Network |
|---|---|---|---|---|---|
| 1 | `hash_gen`, `file_size` | hashes, size | `md5`, `sha1`, `sha256`, `size` | - | - |
| 2 | `ipa.py::extract_and_check_ipa` | unzip, locate `Payload/` (any depth) and the first `*.app` | - | - | - |
| 3 | `file_analysis.py::ios_list_files` | list files (renames `+` -> `x` in place), converts binary plists to XML in place, groups SQLite (`.db .sqlitedb .sqlite .sqlite3`), plist/json, cert/key files | `files`, `file_analysis` | plistlib | - |
| 4 | `plist_analysis.py::plist_analysis` | `Info.plist`: display name, executable, bundle id (`get_bundle_id`: Info.plist, `*.entitlements` app groups, `*.pbxproj` `PRODUCT_BUNDLE_IDENTIFIER`, shortest wins), versions, SDK, platform, min OS, URL types, supported platforms; permissions (`kb/permission_analysis.py::check_permissions`, 23 usage-description keys); ATS (`app_transport_security.py::check_transport_security`) for every plist in scope | `app_name`, `bundle_id`, `build`, `app_version`, `sdk_name`, `platform`, `min_os_version`, `bundle_url_types`, `bundle_supported_platforms`, `info_plist`, `permissions`, `ats_analysis` | plistlib, openstep-parser | - |
| 5 | `appstore.py::app_search` | iTunes lookup by bundle id | `appstore_details` | requests | **Yes**: `GET https://itunes.apple.com/lookup?bundleId=<id>&country=us&entity=software` |
| 6 | `plist_analysis.py::get_plist_secrets` | known-format secrets in every plist + `<key>` lines whose name passes `is_secret_key` and next-line value has no spaces | `secrets` | - | - |
| 7 | `binary_analysis.py::binary_analysis` | main executable (`CFBundleExecutable`, path-safe): `ipa_macho_analysis` (MachOChecksec, symbols, linked libraries with versions), `get_bin_info` (endian, 32/64-bit, CPU type/subtype; first header of a fat binary), `detect_bin_type` (`libswiftCore.dylib` linked -> Swift else ObjC), `classdump.py::get_class_dump`, `binary_rule_matcher.py::binary_rule_matcher` over classdump bytes + newline-joined symbols, `strings_on_binary` | `macho_analysis`, `libraries`, `binary_info`, `app_type`, `binary_analysis`, `strings` | LIEF, macholib, class-dump / class-dump-swift (macOS only), `jtool.ELF64 -arch arm -d objc -v` (Linux), OS `strings`, OS `objdump --syms` (macOS) | - |
| 8 | `lib_analysis.py::library_analysis(..,'macho')` + `frameworks_analysis` | every `*.dylib` and every `X.framework/X` binary: Mach-O checksec, strings, symbols | `dylib_analysis`, `framework_analysis` | LIEF | - |
| 9 | `ios/strings.py::get_strings_metadata` | secrets from binary strings (known + entropy), URL/email extraction from all files (skips `CodeResources`, `/Frameworks/`, binary asset extensions) + binary strings dump + dylib/framework strings | `urls`, `emails`, `secrets`, `strings` | - | - |
| 10 | `MalwareDomainCheck.scan` | as Android | `domains` | IP2Location | **Yes** |
| 11 | `icon_analysis.py::get_icon_from_ipa` | finds `AppIcon*.png`, fixes CgBI PNGs with `CgbiPngFix` binary | `icon_path` | CgbiPngFix (bundled, x86_64/arm64/exe) | - |
| 12 | `ipa.py::common_firebase_and_trackers` | Firebase checks; trackers from domains only (Exodus `network_signature` against registrable domains via tldextract) | `firebase_urls`, `trackers` | tldextract | **Yes** (Firebase, Exodus refresh) |
| 13 | `ios/db_interaction.py::save_get_ctx` + `ipa.py::generate_dynamic_context` | persist, suppression on code + binary findings, `get_ios_dashboard`, `get_avg_cvss(binary_analysis)`, VirusTotal | see D.2 | ORM **[TANGLED]** | VT if enabled |

iOS source zip (`ios_analysis_task`): file listing, plist analysis (all `*.plist` outside `__MACOSX`/`Pods`), App
Store lookup, plist secrets, `code_analysis.py::ios_source_analysis` (libsast with `objective_c_rules.yaml` on `.m`,
`swift_rules.yaml` on `.swift`, merged; `ios_apis.yaml` on both; URL/email extraction; `source_type` = Swift /
Objective-C / both / No Code), `strings_and_entropies` on `.swift .m .h .plist .json`, icon, firebase, trackers.
`binary_analysis` is empty for source zips.

Dylib (`dylib.py::dylib_analysis`, view): `get_bin_info`, `library_analysis('macho')`, symbols into `file_analysis`,
`binary_rule_matcher` on symbols only, strings/secrets/URLs, domains, trackers, firebase.
Static library (`common/a.py::a_analysis`, view): `ar_extract` (arpy; fallback OS `ar`, and `lipo -thin` for fat
archives on macOS), `library_analysis('ar')` picks Mach-O or ELF per `*.o`, then as dylib.

#### iOS module table

| Module | LOC | Key functions | Difficulty | Suggested Rust approach |
|---|---:|---|---|---|
| `ipa.py`, `static_analyzer.py`, `dylib.py`, `common/a.py` | 381+101+173+191 | orchestration | S-M | orchestrator; `ar` crate for archives; goblin handles fat archives/binaries natively so `lipo` is unnecessary |
| `plist_analysis.py`, `app_transport_security.py`, `kb/permission_analysis.py` | 307+240+93 | `plist_analysis`, `get_bundle_id`, `convert_bin_xml`, `get_summary`, `get_plist_secrets`, `check_transport_security`, `check_permissions` | S | `plist` crate (XML + binary); small hand-written OpenStep (`.pbxproj`) parser or a regex for `PRODUCT_BUNDLE_IDENTIFIER`; do not mutate the extracted tree (MobSF rewrites plists and file names in place) |
| `file_analysis.py` | 103 | `ios_list_files` | S | straight port without in-place renames |
| `binary_analysis.py`, `common/binary/macho.py` | 180+337 | `MachOChecksec.*` (`has_nx`, `is_pie`, canary = imports both `___stack_chk_fail` and `___stack_chk_guard`, ARC = imports `_objc_release` or `_swift_release`, `has_rpath`, code signature `data_size>0`, `LC_ENCRYPTION_INFO.cryptid`, stripped via `objdump` or N_STAB scan), `get_libraries`, `get_bin_info`, `detect_bin_type` | M | `goblin::mach` (fat + thin, load commands, symbols, imports); stripped detection natively via nlist N_STAB bits (drop the `objdump` path); code signature via `LC_CODE_SIGNATURE` |
| `classdump.py` | 131 | `get_class_dump`, `classdump_mac`, `classdump_linux` | **L** (native) / S (wrapper) | the rules only need ObjC/Swift class and selector names: parse `__objc_classlist`, `__objc_classname`, `__objc_methname` (and Swift `__swift5_types` names) natively, or keep class-dump/jtool as optional externals. jtool is proprietary freeware; class-dump binaries are macOS-only |
| `binary_rule_matcher.py` + `rules/ipa_rules.py` | 66+221 | `binary_rule_matcher`, `get_desc` | S | byte regex (`regex::bytes`) over classdump + symbols; 10 rules |
| `code_analysis.py` | 154 | `ios_source_analysis`, `merge_findings` | S (given the SAST engine) | reuse SAST engine |
| `ios/strings.py` | 112 | `extract_urls_n_email`, `get_strings_metadata` | S | straight port |
| `appstore.py` | 65 | `app_search` | S | `reqwest` behind `network` feature |
| `icon_analysis.py` | 151 | `get_icon_from_ipa`, `get_icon_source` | M | CgBI PNG fix natively (strip CgBI chunk, raw-deflate IDAT, swap BGRA->RGBA, re-zlib) with `flate2` + `png` |
| `ios/db_interaction.py` | 248 | `get_context_from_analysis` etc. | S | report struct |

### B.3 Windows APPX (note only)

`StaticAnalyzer/views/windows/windows.py` (630 LOC) + `db_interaction.py` (142): unzips the APPX, parses
`AppxManifest.xml` metadata (`_parse_xml`, `parse_xml_metadata`), extracts strings from the first `*.exe`
(`strings_util`) and flags insecure C functions by regex, then runs Microsoft **binskim** (SARIF parsing, old and new
formats) and **binscope** either locally on Windows or via an XML-RPC Windows VM (`install/windows/rpc_client.py`,
`setup.py`, `config.txt`). Not worth porting for the stated consumers; if ever needed, PE checks can be done with
`goblin::pe` (DllCharacteristics: ASLR/DEP/CFG/SafeSEH, GS cookie) instead of binskim. Difficulty: M (native PE
checks) / out of scope (binskim parity).

### B.4 Malware analyzer (`mobsf/MalwareAnalyzer/`, 1,173 LOC)

| Module | LOC | Key functions | Computes | Report keys | Data / libs | Network | Difficulty | Rust approach |
|---|---:|---|---|---|---|---|---|---|
| `views/android/apkid.py` | 90 | `apkid_analysis` | APKiD `Scanner(rules, Options(timeout=30, recursive=True, entry_max_scan_size=256MB)).scan_file(apk)`; JSON `files[]` re-keyed by inner file name (`a.apk!classes.dex` -> `classes.dex`): `{file: {category: [names]}}` | `apkid` | apkid (YARA rules compiled to `rules.yarc`, yara-python) | - | M | `yara-x` with the APKiD `.yara` sources compiled at build time; replicate APKiD's recursive zip/dex walking and filename keys. Verify yara-x supports every module the APKiD rules import (they use the `dex` module) before committing |
| `views/android/permissions.py` | 106 | `check_malware_permission` | membership in 25 `TOP_MALWARE_PERMISSIONS` and 44 `OTHER_PERMISSIONS` | `malware_permissions` | inline lists | - | S | const arrays |
| `views/android/behaviour_analysis.py` + `rules/behaviour_rules.yaml` | 32 + YAML | `analyze` | libsast `RegexAnd` rules on decompiled Java; rule ids in Quark-engine numbering (`00019`, `00058`, ...; likely derived from Quark rules) with `metadata.label` categories | `behaviour` | 211 rules | - | S (with SAST engine) | reuse SAST engine |
| `views/MalwareDomainCheck.py` | 316 | `MalwareDomainCheck.scan/update/update_maltrail_db/malware_check/maltrail_check/gelocation`, `get_domains`, `sanitize_domain`, `verify_domain`, `get_netloc` | lowercases URLs, extracts hostnames, sanitises (cut at `_`, strip non `\w.-`, trim `-`), requires `.` and len>2; marks `bad` via malwaredomainlist CSV (column 1 netloc or column 2 IP prefix) and maltrail exact-line match; geolocation via DNS (public IPs only) + IP2Location; OFAC flag if country/region/city in a 32-entry list | `domains` | `signatures/malwaredomainlist`, `signatures/maltrail-malware-domains.txt`, `signatures/IP2LOCATION-LITE-DB5.IPV6.BIN` | maltrail refresh (GitHub, 120 s timeout) every scan when online; DNS lookups; connectivity probe | S-M | `HashSet<String>` for maltrail (991k lines, consider an FST via `fst` crate); IP2Location BIN reader is a small binary-search format reader (or swap to MaxMind with `maxminddb`, changing fields); `hickory-resolver` + public-IP filter; make DB refresh an explicit API |
| `views/Trackers.py` | 280 | `Trackers.get_trackers`, `get_trackers_domains_or_deps`, `detect_trackers_in_list`, `get_embedded_classes`, `load_trackers_signatures`, `_update_tracker_db` | class names from DEX (baksmali `list classes`) matched with `re.search(code_signature)` (sigs with len>3); domains reduced to registrable domain (`tldextract`) matched with `network_signature` | `trackers` | `signatures/exodus_trackers` (432 trackers) | Exodus API refresh every scan when online | S-M | read DEX `class_defs`/`type_ids` natively (smali-style `Lcom/foo/Bar;` descriptors converted to dotted names to match Exodus signatures, as baksmali prints); `psl` or `publicsuffix` crate for registrable domain; `RegexSet` for speed |
| `views/VirusTotal.py` | 349 | `VirusTotal.get_result/get_report/upload_file/_get_upload_url/_poll_analysis/_normalize_report` | VT v3 lookup by MD5, optional upload (direct <=32 MB or `upload_url`), short poll, normalised to the legacy v2 shape | `virus_total` | - | **Yes** `https://www.virustotal.com/api/v3/files...` (API key) | S | `reqwest`; optional feature |

There is no Quark engine dependency in v4.5.3: "behaviour" analysis is the libsast `behaviour_rules.yaml`, and the
DB column is still named `QUARK`.

### B.5 Dynamic analyzer

`mobsf/DynamicAnalyzer/` is 9,238 Python LOC plus ~10.7k lines of Frida JS shipped as data. There are three paths:
**Android** (adb + Frida, legacy Xposed), **iOS on Corellium** (REST API + SSH bastion), and the newer **iOS
physical/local device** path (`views/ios/device/`, SSH over USB/WiFi). `frida>=17` is pinned, so the Frida-17 bridge
path (`views/common/frida/bridge_loader.py`) is the live path.

#### B.5.1 Android dynamic

| File | LOC | Key functions | Purpose |
|---|---:|---|---|
| `views/android/environment.py` | 733 | `Environment.connect`, `connect_n_mount`, `install_apk`, `adb_command`, `configure_proxy`, `install_mobsf_ca`, `set_global_proxy`/`unset_global_proxy`, `enable_adb_reverse_tcp`, `start_clipmon`, `screen_shot`/`screen_stream`, `get_environment`, `get_android_version/_arch/_sdk`, `get_device_packages`, `get_apk`, `system_check`, `run_app`, `is_mobsfyied`, `mobsfy_init`, `mobsf_agents_setup`, `xposed_setup`, `frida_setup`, `run_frida_server` | all adb orchestration, system CA install, proxy, "MobSFy" provisioning, frida-server push/start. `ANDROID_API_SUPPORTED = 30` (higher API rejected) |
| `views/android/dynamic_analyzer.py` | 348 | `android_dynamic_analysis`, `dynamic_analyzer`, `httptools_start`, `logcat`, `trigger_static_analysis` | views; the connect -> mobsfy -> proxy -> install sequence lives in the view body **[TANGLED]** |
| `views/android/operations.py` | 332 | `mobsfy`, `execute_adb`, `run_apk`, `take_screenshot`, `screen_cast`, `touch`, `mobsf_ca`, `global_proxy` | AJAX wrappers over `Environment` |
| `views/android/tests_common.py` | 291 | `start_activity`, `start_deeplink`, `activity_tester`, `download_data` (tar of `/data/data/<pkg>`), `collect_logs`, `tls_tests` | activity/deeplink exercising, data pull, TLS orchestration **[TANGLED]** |
| `views/android/frida_core.py` | 300 | `Frida.get_scripts/get_auxiliary/get_script/frida_response/spawn/session/ps/api_handler/clean_up/write_log` | session management, script composition, message routing, RPC |
| `views/android/tests_frida.py` | 295 | `instrument`, `live_api`, `apimon_analysis`, `get_runtime_dependencies`, `dependency_analysis`, `decode_base64` | Frida instrument view + API-monitor / runtime-dependency post-processing |
| `views/android/tests_tls.py` | 107 | `run_tls_tests`, `detect_traffic` | 3-stage TLS test (below) |
| `views/android/tests_xposed.py` | 194 | `droidmon_api_analysis`, `get_hooked_apis`, `download_xposed_log` | legacy Xposed/Droidmon (Android < 5 only) |
| `views/android/analysis.py` | 214 | `run_analysis`, `get_screenshots`, `get_tls_logs`, `get_log_data`, `generate_download` | aggregates logcat/web/Frida/API logs -> URLs/domains/emails; download bundle |
| `views/android/report.py` | 107 | `view_report` | report assembly in the view **[TANGLED]** |
| `views/android/frida_scripts.py` | 61 | `get_loaded_classes`, `string_catch`, `string_compare`, `get_methods`, `class_pattern`, `class_trace` | auxiliary JS loading with `{{CLASS}}`/`{{PATTERN}}` substitution |
| `tools/webproxy.py` | 121 | `start_proxy`, `start_httptools_ui`, `stop_httptools`, `create_ca`, `get_ca_file`, `get_traffic` | `httptools` (MobSF http-tools, mitmproxy-based) wrapper, shared with iOS |
| `tools/apk_patcher.py` | 103 | `GadgetPatcher` | Frida-gadget injection via apktool 2.7.0; **dead code** (no importer) |
| `views/common/shared.py`, `device.py` | 188+104 | `extract_urls_domains_emails`, `untar_files`, `get_app_files`, `view_file` | shared Android/iOS post-processing; reuses `MalwareDomainCheck` |
| `views/common/frida/{bridge_loader,server_update,views}.py` | 122+128+112 | `FridaBridgeLoader`, `FridaServerUpdater`, `list_frida_scripts`, `frida_logs` | Frida 17 bridge injection, frida-server download, script listing |

- **adb operations** (via `adb -s <id> [shell] ...`): `connect`, `kill-server`/`start-server`, `root`, `remount`,
  `devices`; `getprop` (serials, Genymotion markers, `ro.build.version.release`, `ro.product.cpu.abi`,
  `ro.build.version.sdk`); `pm list packages [-f -3]`, `pm path`, `install -r -t -d`, `uninstall`, `md5sum -b`;
  `settings put global verifier_verify_adb_installs 0`; `settings put/delete global http_proxy ...`,
  `reverse tcp:1337 tcp:1337`; `push <ca>.pem /system/etc/security/cacerts/<subject_hash>.0` + `chmod 644`;
  `am start -n`, `am start -a android.intent.action.VIEW -d <url>`, `am startservice` (ClipDump), `am force-stop`,
  `monkey -p <pkg> -c LAUNCHER 1`, `input tap/swipe/text/keyevent`; `screencap -p` + `pull`; `tar -cvf` of
  `/data/data/<pkg>` + `pull`; `logcat -d`, `dumpsys`; `push frida-server /system/fd_server`, `chmod 755`, start in a
  daemon thread; marker files `/system/.mobsf-f` / `.mobsf-x`.
- **Device requirements**: writable `/system` (effectively rooted emulator: Android Studio AVD, Genymotion, or
  Corellium Android), API <= 30; Android < 5 uses Xposed, >= 5 uses Frida; adb reverse needs 5+.
- **Frida script composition** (`Frida.get_script`): custom code + selected `default` scripts + all `rpc` scripts
  merged into `rpc.exports` + auxiliary scripts, wrapped in `setTimeout(...,1000)`; for Frida >= 17 the
  `frida_tools/bridges/java.js` (Android) or `objc.js` (iOS) text is prepended and bound to `globalThis.Java/ObjC`.
- **Frida script inventory** (`tools/frida_scripts/`):

  | Dir | Files | Lines | Default |
  |---|---:|---:|---|
  | `android/default` | 5 | 1,609 | all on: `api_monitor`, `ssl_pinning_bypass`, `root_bypass`, `debugger_check_bypass`, `dump_clipboard` |
  | `android/rpc` | 1 | 65 | always (`get-hooks.js`: loaded classes, methods, implementations) |
  | `android/auxiliary` | 6 | 261 | user-selected (class_trace, get_loaded_classes, get_methods, search_class_pattern, string_catch, string_compare) |
  | `android/others` | 46 | 5,626 | off (library of snippets) |
  | `ios/default` | 1 | 219 | `jailbreak_bypass` on; SSL pinning bypass is RPC-invoked |
  | `ios/rpc` | 3 | 365 | always (`get-app-container`, `screenshot`, `ssl-pinning`) |
  | `ios/dump` | 13 | 893 | all on (network, crypto, cookies, file-access, json, sqlite, data-dir, keychain, nslog, text-inputs, nsurlcredentialstorage, nsuserdefaults, pasteboard) |
  | `ios/auxiliary` | 8 | 436 | user-selected |
  | `ios/others` | 35 | 1,201 | off |

- **Frida output routing** (`frida_response`, files in `uploads/<md5>/`): `MobSF-API-Monitor: ` ->
  `mobsf_api_monitor.txt`; `mobsf-android-clipboard:` -> `mobsf_app_clipboard.txt`; `[RUNTIME-DEPS] ` ->
  `mobsf_app_deps.txt`; `[AUXILIARY] ` and everything else -> `mobsf_frida_out.txt`; RPC results ->
  `mobsf_rpc_classes.txt` / `mobsf_rpc_methods.txt` / `mobsf_rpc_impl.txt`. `api_monitor.js` hooks ~120 methods in 18
  categories.
- **Proxy**: `httptools -m capture -p <port> -n <project> [-u <upstream>]` and `httptools -m server` for the UI; CA
  created by running `mitmdump -n` once and reading `~/.mitmproxy/mitmproxy-ca-cert.pem`; subject-hash filename via
  pyOpenSSL; traffic read back from `~/.httptools/flows/<package>.flow.txt`; stopped via `GET
  http://127.0.0.1:<port>/kill` and a proxied request with header `httptools: kill`. Default `PROXY_PORT=1337`.
- **TLS tests** (`run_tls_tests`, ~25 s per stage, writes `mobsf_tls_tests.json`): (1) CA removed: HTTPS seen ->
  `tls_misconfigured`, HTTP seen -> `has_cleartext`; (2) CA installed: HTTPS seen -> `no_tls_pin_or_transparency`;
  (3) Frida with `ssl_pinning_bypass`, `debugger_check_bypass`, `root_bypass`: HTTPS seen ->
  `pin_or_transparency_bypassed`. `detect_traffic` regex-matches `METHOD https://` vs `http://` in the flow dump.
- **Xposed**: Android < 5 only; installs bundled `Xposed.apk`, `XposedInstaller_3.1.5.apk`, `ClipDump.apk` and modules
  (`Droidmon`, `JustTrustMe`, `rootcloak2`, `proxyon`, `sslunpinning`, `AndroidBluePill`) + `hooks.json`. Legacy;
  defer/drop.
- **Report keys** (`report.py::view_report`): `urls`, `domains`, `emails`, `clipboard`, `xml`, `sqlite`, `others`,
  `tls_tests` {`tls_misconfigured`, `has_cleartext`, `no_tls_pin_or_transparency`, `pin_or_transparency_bypassed`},
  `screenshots`, `activity_tester`, `exported_activity_tester`, `droidmon`, `apimon` (by category), `base64_strings`,
  `trackers` (domains + runtime deps), `frida_logs`, `runtime_dependencies`.

#### B.5.2 iOS dynamic on Corellium

| File | LOC | Key functions | Purpose |
|---|---:|---|---|
| `views/ios/corellium_apis.py` | 643 | `CorelliumAPI`, `CorelliumModelsAPI`, `CorelliumInstanceAPI`, `CorelliumAgentAPI` | REST client: projects/keys, models/firmware, instance lifecycle, screenshot, sslsplit network capture, console log, quick-connect string, input; agent: unlock, upload/install IPA, run/kill/uninstall, list apps, icons |
| `views/ios/corellium_instance.py` | 944 | instance lifecycle views, `setup_environment`, AppSync install, `network_capture`, `ssh_execute`, `download_app_data`, `upload_file`/`download_file` | orchestration inside AJAX views; module-global `SSH_TARGET` **[TANGLED]** |
| `views/ios/corellium_ssh.py` | 292 | `generate_keypair_if_not_exists` (Ed25519), `parse_ssh_string`, `ssh_jump_host`, local + reverse port-forward servers, `ssh_execute_cmd`, SFTP upload/download | paramiko over the Corellium bastion (`root`/`alpine`) |
| `views/ios/frida_core.py` | 353 | `Frida` (also base class for the device path), `frida_ssh_forward` (local-forward 27042), RPC `get_container`, `get_screenshot`, `bypass_ios_ssl_pinning` | Frida via SSH tunnel |
| `views/ios/{dynamic_analyzer,analysis,report,helpers,tests_frida,frida_auxiliary_scripts}.py` | 150+124+95+296+122+69 | `dynamic_analysis`, `run_analysis`, `ios_api_analysis`, `ios_view_report`, `configure_proxy`, `get_ios_model_mapping`, `ios_instrument` | dump parsing, report, proxy + reverse forward of 1337 |

- Output routing: `[MBSFDUMP] ` -> `mobsf_dump_file.txt` (JSON per line); others -> `mobsf_frida_out.txt`; container
  path -> `mobsf_app_container_path.txt`.
- AppSync over SSH: adds `deb https://cydia.akemi.ai/ ./`, `apt update`, `apt install ai.akemi.appinst`,
  `launchctl reboot userspace`, `appinst /tmp/app.ipa`. App data: `tar -C <container> -cvf ...` then SFTP.
- Requirements: jailbroken Corellium iOS instance, `CORELLIUM_API_KEY` (+ optional project id),
  `CORELLIUM_API_DOMAIN` (env; Corellium cloud is `https://app.corellium.com`).
- Report keys (`analysis.py::ios_api_analysis` + `run_analysis`): `cookies`, `crypto`, `network`, `files`,
  `keychain`, `logs`, `credentials`, `userdefaults`, `pasteboard`, `textinputs`, `datadir`, `sql`, `json`, `sqlite`,
  `plist`, `others`, `urls`, `domains`, `emails`, `trackers`, `screenshots`, `frida_logs`.

#### B.5.3 iOS dynamic on a physical / local device (`views/ios/device/`)

| File | LOC | Key functions | Purpose |
|---|---:|---|---|
| `connect.py` | 448 | `IOSConnector.connect_usb/connect_wifi/get_usb_devices/_setup_usb_port_forward/...` | paramiko SSH over `iproxy` (USB, libimobiledevice) or WiFi; root check |
| `device.py` | 508 | `IOSDevice.execute_command/ps/install_deb/install_apt_package/install_ipa/list_applications/get_app_icon/...` | device ops over SSH/SFTP |
| `dynamic_analyzer.py` | 504 | `dynamic_analyzer_device`, `ios_instrument_device`, `validate_and_connect_device`, ... | views with heavy logic **[TANGLED]** |
| `environment.py` | 319 | `IOSEnvironment.setup_or_start_frida`, `_install_frida_server_on_device`, `_modify_frida_plist_for_wifi`, `install_oslog` | frida-server `.deb` install, launchd plist patch (`-l 0.0.0.0`), oslog install |
| `frida.py` | 179 | `FridaIOSDevice(Frida)` | `add_remote_device(host:37042)` instead of SSH tunnel |
| `report.py` | 314 | `view_report_device`, `download_app_data_device`, `ios_api_monitor` | report (reuses `ios/analysis.py`) |

- External binaries: `idevice_id`, `ideviceinfo`, `iproxy` (2222->22, 37042->27042), `xcrun pngcrush` (macOS) or
  bundled `CgbiPngFix`. Bundled `.deb`s: `tools/ios/appsync/*` (AppSync Unified 116.0 arm/arm64),
  `tools/ios/oslog/*`. On-device commands: `id`, `ps aux`, `arch`, `dpkg -i`, `apt-get install -y`, `uicache -l`,
  `launchctl load/unload`, `frida-server -l 0.0.0.0`, `oslog [-p pid]`, `tar`, `appinst`.

#### B.5.4 Dynamic difficulty and approach

| Concern | Size | Approach |
|---|---|---|
| Frida JS (all dirs) | data | ship unchanged as embedded assets; port only selection/templating (`frida_scripts.py`, `frida_auxiliary_scripts.py`) and bridge concatenation |
| Frida session/RPC (Android + iOS `frida_core.py`) | L | `frida-rust` bindings (device manager, spawn, attach, script messages, RPC) |
| adb layer (`environment.py`, `operations.py`) | L | shell out to `adb` (keeps parity) or an adb client crate; keep command strings as data |
| proxy + CA (`webproxy.py`) | S-M | keep shelling out to `httptools`/`mitmdump`, or replace with a Rust MITM proxy (e.g. `hudsucker`) and `rcgen` CA; subject hash via `x509-cert` + OpenSSL-compatible hash |
| frida-server download | S | `reqwest` + `xz2` |
| post-processing (`analysis.py`, `tests_frida.py`, `shared.py`, iOS `analysis.py`) | M | pure parsing (`serde_json`, `regex`, `tar`, `rusqlite`); port these first |
| TLS tests | M | state machine over proxy + Frida |
| Xposed + `apk_patcher.py` | S | defer/drop (legacy and dead) |
| Corellium REST (`corellium_apis.py`) | L | `reqwest` client (~30 endpoints) |
| SSH with jump host + local/reverse forwards (`corellium_ssh.py`, device `connect.py`) | L | `russh` (pure Rust) or `ssh2` (libssh2); the forwarding handlers are the hard part |
| Corellium/device views (`corellium_instance.py`, device `dynamic_analyzer.py`) | XL | split into a service layer first |

Overall: Android dynamic **L**, iOS Corellium **L-XL**, iOS device **XL**.

---

## C. Rule and data files

### C.0 The libsast rule engine (what a Rust port must reproduce)

MobSF uses **libsast 3.1.8** (LGPL-3.0-or-later; `PatternMatcher` and `ChoiceMatcher` only; its semgrep path is
never used). Verified by reading `libsast/core_matcher/{pattern_matcher,matchers,helpers,choice_matcher}.py`.

**Pattern rule schema (YAML list):**

```yaml
- id: android_insecure_ssl          # unique key in output
  message: Insecure Implementation of SSL ...   # becomes metadata.description
  type: RegexAnd                    # Regex | RegexAnd | RegexOr | RegexAndNot | RegexAndOr
  pattern: [ 'javax\.net\.ssl', 'TrustAllSSLSocket-Factory|...' ]
  severity: high                    # high | warning | info | good  (becomes metadata.severity)
  input_case: exact                 # exact | lower | upper  (transforms the CONTENT, not the pattern)
  metadata: {cvss: 7.4, cwe: cwe-295, owasp-mobile: m3, masvs: network-3, ref: https://...}
```

- **Pattern shapes:** `Regex` takes a string. `RegexAnd` and `RegexOr` take a string or a list.
  `RegexAndNot` takes `[present, not]`. `RegexAndOr` takes `[and_regex, [or_1, or_2, ...]]`.
- **Metadata expansion** (`standards.get_mapping`). When a metadata key is one of `cwe`, `masvs`, `owasp-mobile`,
  `owasp-mobile-2024` or `owasp-web`, its value is looked up in libsast's bundled standards YAMLs. Examples:
  `cwe-295` becomes "CWE-295: Improper Certificate Validation" and `network-3` becomes `MSTG-NETWORK-3`. Unknown
  values pass through. The standards files hold cwe 528, masvs 84, mobile-2016 10, mobile-2024 10 and web-2017 10
  entries.
- **Matcher semantics** (each returns a set of `(match_text, (start,end), (line_from,line_to))`; empty matches dropped;
  Python `re`, no flags):
  - `Regex`: all `finditer` matches.
  - `RegexAnd`: every pattern must match at least once, otherwise no finding; returns the union of all matches.
  - `RegexOr`: union of all patterns' matches.
  - `RegexAndNot`: if `not` is found anywhere (`search`), no finding; otherwise the `present` matches.
  - `RegexAndOr`: the `and` matches plus the matches of the **first** or-pattern that matches (later ones are not
    evaluated); both sides must be non-empty.
- **Per-file preprocessing:**
  1. The file is read as UTF-8 with invalid bytes dropped. Universal newlines apply, so line endings become `\n`.
  2. Files over **5 MB** are skipped, and so are files whose lowercased suffix is not in `match_extensions`.
  3. Comments are stripped:
     - `.xml`/`.html`: `<!--...-->`.
     - Everything else: `/\*[\S|\s]+?\*/` first, then `//.+`.
     - Each comment's non-whitespace characters are replaced by spaces, so offsets and line numbers are kept. The
       replacement uses `str.replace` and hits every identical occurrence in the file.
     - A comment is kept if it is exactly `//`, or if `':' + comment` occurs in the file (URL heuristic).
     - Stripping is disabled for the whole file if the text `ignore:` appears anywhere.
- **Positions and lines:**
  - Positions are Python code-point offsets into the stripped, case-transformed text. A start of 0 is rewritten
    to 1.
  - Line numbers come from cumulative `len(line)+1` sums compared with `>=`. Because of this, a match starting at
    column 0 of line N>1 is reported as starting on line N-1.
  - A Rust port should store byte offsets and convert them, and replicate the off-by-one if line-level parity
    matters.
- **Path filters:**
  - `ignore_paths`: substring on the POSIX path. MobSF passes `SKIP_CLASS_PATH`.
  - `ignore_filenames`: fnmatch on the file name.
  - `ignore_extensions`: lowercased suffix.
- **Execution:**
  - Files are read once with a thread pool, then rules run per file in a process pool (`default`), a `billiard` pool
    or a thread pool. MobSF picks the pool in `sast_engine.get_multiprocessing_strategy`.
  - MobSF reads the decompiled tree once (`SastEngine.read_files`) and runs several rule sets on the same contents.
    It creates a fresh engine per rule set because findings accumulate on the matcher instance.
  - Rust: `rayon` over files, `RegexSet` prefilter per rule set, results merged with a `BTreeMap` keyed by rule id.
- **Output**:
  - libsast returns `{rule_id: {files: [{file_path, match_string, match_position, match_lines}], metadata:
    {...rule.metadata, description, severity}}}`, with files sorted by `(path, match_string, lines)`.
  - MobSF's `SastEngine.format_findings` turns `files` into `{relative_path: "a,b,c"}`. The value is the expanded
    line ranges joined with commas; repeated hits in the same file are appended, so line numbers can repeat. Match
    strings and offsets are dropped.

**ChoiceMatcher (NIAP only, disabled by default)**:

- **Schema:** `{id, type: code|manifest, choice_type: or|and|all, message, selection: 'The application {} ...',
  choice: [[regex | [regexes], text], ...], else?, class}`.
- **File scope:** `manifest` rules scan only `alternative_path`, which is the decoded `AndroidManifest.xml`. `code`
  rules scan `.java` and `.xml` files.
- **Choice types:**
  - `or`: the first choice whose regex `search`es.
  - `and`: the first choice whose regexes all match.
  - `all`: the set of texts of all matching choices, formatted as a Python list repr.
- **Output:** `{id: {choice: <selection formatted>, description: message, class: ...}}`.
- **Quirk:** the result is overwritten per file, so the last file processed wins. The order is nondeterministic
  because it iterates a set.

### C.1 Rule files (YAML)

| Path | Format | Size | Rules | Breakdown | Schema / notes |
|---|---|---:|---:|---|---|
| `StaticAnalyzer/views/android/rules/android_rules.yaml` | libsast pattern YAML | 25.8 KB | 52 | Regex 14, RegexAnd 21, RegexOr 12, RegexAndOr 5; high 18, warning 11, info 7, good 16; `input_case: lower` x2 | full schema with `metadata{cvss,cwe,owasp-mobile,masvs,ref}` (ref on 42). Scanned on decompiled `.java`/`.kt`. Report key `code_analysis` |
| `.../android/rules/android_apis.yaml` | libsast pattern YAML | 10.8 KB | 54 | Regex 7, RegexAnd 24, RegexAndOr 13, RegexOr 10; all `info` | no metadata; ids like `api_native_code`, `api_dexloading`. Report key `android_api` |
| `.../android/rules/android_permissions.yaml` | libsast pattern YAML | 158.6 KB (5,547 lines) | 296 | all RegexAndOr, all `info` | `id` = permission name (e.g. `android.permission.SET_WALLPAPER`); pattern `[class-regex alternation, [method-call regexes]]`; only rules whose id is a requested permission are run (written to a temp YAML). Header: generated with axplorer up to API 25, partly with ChatGPT. Report key `permission_mapping` (`{perm: {file: lines}}`) |
| `.../android/rules/android_niap.yaml` | libsast choice YAML | 13.7 KB | 25 | type code 22 / manifest 3; or 17, and 4, all 4; class SFR 9, Selection-Based 15, Optional 1 | NIAP Protection Profile requirement ids (`FCS_RBG_EXT.1.1`, `FDP_DEC_EXT.1.1`, ...). Report key `niap_analysis` |
| `MalwareAnalyzer/views/android/rules/behaviour_rules.yaml` | libsast pattern YAML | 60.4 KB | 211 | all RegexAnd, all `info` | `metadata.label: [..]` (33 distinct labels; collection 84, sms 33, command 27, file 25, network 24, reflection 20, telephony 16, ...); numeric ids such as `00019`, `00058` (matching Quark-engine rule numbering; provenance inferred). Report key `behaviour` |
| `StaticAnalyzer/views/ios/rules/objective_c_rules.yaml` | libsast pattern YAML | 13.2 KB | 25 | Regex 13, RegexAnd 8, RegexAndOr 2, RegexOr 2; good 6, high 7, info 6, warning 6 | full metadata; run on `.m`. Report key `code_analysis` (iOS source) |
| `.../ios/rules/swift_rules.yaml` | libsast pattern YAML | 19.1 KB | 39 | Regex 18, RegexAnd 11, RegexAndNot 1, RegexAndOr 1, RegexOr 8; good 10, high 9, info 5, warning 15 | full metadata; 4 inline `(?i)` groups; run on `.swift` |
| `.../ios/rules/ios_apis.yaml` | libsast pattern YAML | 1.8 KB | 13 | Regex 10, RegexAnd 3; all `info` | run on `.m` + `.swift`. Report key `ios_api` |
| libsast `standards/*.yaml` (in the libsast package) | YAML maps | - | 642 entries | cwe 528, masvs 84, owasp-mobile 2016/2024 10+10, web 10 | short code -> display string |

Totals across the 7 pattern files: 690 rules (Regex 62, RegexAnd 278, RegexOr 32, RegexAndNot 1, RegexAndOr 317);
`input_case` exact 686, lower 4.

### C.2 Rule tables embedded in Python

| Location | Count | Schema / description |
|---|---:|---|
| `StaticAnalyzer/views/android/kb/android_manifest_desc.py::MANIFEST_DESC` | 53 templates | `{rule_key: {title, level (high 7 / warning 32 / info 14), description, name}}`; `%s` placeholders filled from the tuples emitted by `manifest_analysis` (`(key, title_args, desc_args)`). Keys: `well_known_assetlinks, clear_text_traffic, direct_boot_aware, has_network_security, vulnerable_os_version, vulnerable_os_version2, app_is_debuggable, app_allowbackup, allowbackup_not_set, app_in_test_mode, task_affinity_set, non_standard_launchmode, task_hijacking, task_hijacking2, improper_provider_permission, dialer_code_found, sms_receiver_port_found, high_intent_priority_found, high_action_priority_found`, 13 `exported_protected_permission*` / `explicitly_exported` / `exported_intent_filter_exists`, and 21 `exported_provider*` variants |
| `.../android/manifest_analysis.py` (decision logic) | ~20 check families | thresholds: minSdk < 26 -> `vulnerable_os_version`, < 29 -> `vulnerable_os_version2`; launchMode singleTask/singleInstance with minSdk < 21; StrandHogg 1 (targetSdk < 28 + singleTask), StrandHogg 2 (targetSdk < 29 + exported + not singleInstance or taskAffinity set); provider implicit export when minSdk < 17 and targetSdk < 17 (or >= 17 variant); intent-filter/action priority > 100; grant-uri-permission `/` or `*`; `android_secret_code` scheme; data port. Exported-component matrix: component permission vs application permission x protectionLevel (normal/dangerous/signature/signatureOrSystem/undefined). `ANDROID_API_LEVEL_MAP` 1-36 |
| `.../android/kb/dvm_permissions.py::DVM_PERMISSIONS` | 392 + 22 + 11 | `MANIFEST_PERMISSION{short_name: [protection, label, description]}` (392), `SPECIAL_PERMISSIONS{full_name: [...]}` (22 launcher badge perms), `MANIFEST_PERMISSION_GROUP` (11, unused). LGPL-3 androguard header |
| `.../android/network_security.py` | 17 checks | base-config cleartext true(high)/false(secure); trust-anchors `@raw/` (info), `system` (warning), `user` (high), `overridePins` (high); same for domain-config with `scope=[domains]`; pin-set with/without expiration (info/secure); debug-overrides only when debuggable (cleartext high, `@raw/` high, overridePins high) |
| `.../android/cert_analysis.py` | 5 findings + extension lists | signed (info) / not signed (high); Janus v1 (high, warning if v2/v3 present and API < 27); debug cert `CN=Android Debug` (high); SHA1 (high, warning if `SHA-256-Digest` in MANIFEST.MF); MD5 (high). Cert/key extensions 9, keystore extensions 2 |
| `.../common/binary/elf.py::ELFChecksec` | 8 checks | `nx`, `pie`, `stack_canary`, `relocation_readonly`, `rpath`, `runpath`, `fortify`, `symbol`; each `{value, severity, description}` |
| `.../common/binary/macho.py::MachOChecksec` | 8 checks | `nx`, `pie`, `stack_canary`, `arc`, `rpath`, `code_signature`, `encrypted`, `symbol` |
| `.../ios/rules/ipa_rules.py::IPA_RULES` | 10 | `{description, detailed_desc ('...{}'), type 'Regex', pattern (bytes regex, some with literal `\n` anchors because symbols are newline-joined), severity (warning 6 / info 4), input_case, cvss, cwe, owasp-mobile, masvs}` (standards expanded via `libsast.standards.get_standards()`). Rules: insecure C APIs, weak crypto APIs, crypto APIs, weak hashing APIs, hash APIs, insecure random, logging (NSLog), malloc, ptrace anti-debugging, WebView usage. Matched against class-dump output + symbols |
| `.../ios/app_transport_security.py` | ~13 checks | `NSAllowsArbitraryLoads`, `...ForMedia`, `...InWebContent`, `NSAllowsLocalNetworking` (high); `NSExceptionDomains` (info list); per domain: insecure HTTP loads (high, skips localhost/127.0.0.1), `NSIncludesSubdomains` (info), min TLS 1.0/1.1 (high) / 1.2 (warning) / 1.3 (secure) / other (info), forward secrecy NO (high), certificate transparency NO/absent (warning) / YES (secure) |
| `.../ios/kb/permission_analysis.py::COCOA_KEYS` | 23 | `{plist_key: (info, 'normal'\|'dangerous')}`; report adds the app's usage string as `description` |
| `.../common/firebase.py::FIREBASE_FINDINGS` | 6 | `firebase_db_open` (high), `firebase_db_exists` (info), `firebase_db_check_failed` (info), `firebase_remote_config_enabled` (warning), `..._disabled` (secure), `..._failed` (info) |
| `.../common/secret_detection.py::KNOWN_SECRET_PATTERNS` | 22 | named regexes (GitHub classic + fine-grained, GitLab PAT, Slack token + webhook, Stripe live, SendGrid, npm, Mapbox secret, Anthropic, OpenAI, Hugging Face, DigitalOcean, Doppler, Brevo, Sentry, Shopify, Square, PEM private key, Amazon LWA secret/access/refresh); output `"<name>: <match>"`, sorted before heuristic secrets |
| `.../common/entropy.py::ENTROPY_PATTERNS` | 2 | base64-ish `[a-zA-Z\d+/=]{20,}` with Shannon entropy > 4.5, hex `[a-fA-F\d-]{20,}` > 3.0; only for strings of length >= 21; excludes JVM descriptors, `kotlin/`, `abcdefghi`, >1 slash, pure alpha |
| `.../common/shared_func.py::is_secret_key` | 11 / 23 / 33 | key-name heuristic: endswith list, contains list, must-not-contain list |
| `MobSF/utils.py` regexes | 6 used by core | `URL_REGEX` (http/https/ftp/sftp/file/javascript/data/www), `EMAIL_REGEX`, `STRINGS_REGEX` (look-around: text between quotes or `<string>` tags), `GOOGLE_API_KEY_REGEX` (`AIza...`), `GOOGLE_APP_ID_REGEX`, `PKG_REGEX` |
| `MalwareAnalyzer/views/android/permissions.py` | 25 + 44 | `TOP_MALWARE_PERMISSIONS`, `OTHER_PERMISSIONS` |
| `MalwareAnalyzer/views/MalwareDomainCheck.py` | 32 | OFAC country/region list |
| `MobSF/settings.py::SKIP_CLASS_PATH` | 24 | third-party path substrings skipped by code analysis |
| `StaticAnalyzer/views/windows/windows.py` | 1 regex | insecure C function names in APPX strings |

### C.3 Data files

| Path | Format | Size | Entries | Description |
|---|---|---:|---:|---|
| `signatures/exodus_trackers` | JSON `{trackers: {id: {id, name, description, creation_date, code_signature, network_signature, website, categories[], documentation[]}}}` | 572 KB | 432 trackers (428 usable code signatures, 260 network signatures) | Exodus Privacy tracker DB snapshot; `code_signature` is a regex alternation of package prefixes (e.g. `com.databerries.\|com.geolocstation.`), `network_signature` a domain regex. Auto-refreshed from the Exodus API |
| `signatures/maltrail-malware-domains.txt` | text, one domain per line, `#` header | 19.1 MB | ~991,323 domains | Maltrail malware trails; exact-match lookup; auto-refreshed from GitHub. Data licence: Maltrail Trails Community Data License 1.0 (restricts use in third-party products) |
| `signatures/malwaredomainlist` | quoted CSV (`date, domain/URL, IP, reverse, description, registrant, ASN, inactive, country`) | 325 KB | 2,255 rows | legacy malwaredomainlist.com dump (2009+); `MALWARE_DB_URL` exists in settings but is unused; no licence file |
| `signatures/IP2LOCATION-LITE-DB5.IPV6.BIN` | IP2Location BIN (DB5: country, region, city, lat, long; IPv4+IPv6) | 99.2 MB | n/a | geolocation for resolved domain IPs; IP2Location LITE licence (attribution) |
| `StaticAnalyzer/tools/androguard4/resources/public.xml` | XML `<public type= name= id=>` | 187 KB | 2,480 | Android framework public resource ids for AXML attribute name/ref resolution |
| `DynamicAnalyzer/tools/frida_scripts/**` | JavaScript | 10.7k lines | 118 files | see B.5.1 |
| `DynamicAnalyzer/tools/onDevice/xposed/modules/hooks.json` | JSON | 11.8 KB | - | Droidmon hook list (legacy) |
| apkid package `apkid/rules/rules.yarc` | compiled YARA | 4.4 MB | 360 rules (21 `.yara` sources at APKiD v3.1.0) | anti_vm, anti_debug, anti_disassembly, anti_root, compiler, packer, protector, obfuscator, manipulator, abnormal, dropper, embedded, file_type |

---

## D. Final static-analysis JSON report key trees

**Report endpoints.** Three paths produce or reshape the report:

- `POST /api/v1/report_json` calls `MobSF/views/api/api_static_analysis.py::api_json_report`, which calls
  `StaticAnalyzer/views/common/pdf.py::pdf(api=True, jsonres=True)`. That builds the context from the DB
  (`get_context_from_db_entry`), then adds `average_cvss`, `appsec`, `virus_total`, `base_url`, `dwd_dir`, `host_os`
  and `timestamp`.
- `POST /api/v1/scan` returns the in-memory context from `get_context_from_analysis` plus `appsec` and
  `average_cvss`. For Android APKs it also adds `dynamic_analysis_done` and `virus_total`.
- Both pass findings through `suppression.py::process_suppression*`, which wraps them as `{findings, summary}` or
  `{manifest_findings, manifest_summary}`.

### D.1 Android (APK; JAR/AAR/SO/source zip fill the same keys, some empty)

```
version                     MobSF version string
title                       "Static Analysis"
file_name                   uploaded file name
app_name                    app label (androguard / aapt2 / res/values app_name)
app_type                    'apk' | 'jar' | 'aar' | 'so' | 'eclipse' | 'studio'
size                        "<n>MB"
md5 / sha1 / sha256         file hashes (md5 is the scan id)
package_name                manifest package
main_activity               launcher activity
exported_activities         [str] exported activity names
browsable_activities        {activity: {schemes[], mime_types[], hosts[], ports[], paths[], path_prefixs[],
                             path_patterns[], browsable: bool, well_known: {assetlinks_url: scheme://host}}}
activities / services / receivers / providers / libraries   [str] from manifest
target_sdk / max_sdk / min_sdk   str
version_name / version_code      str
icon_path                   path of extracted icon (relative to downloads)
permissions                 {perm: {status: normal|dangerous|signature|...|unknown, info: label, description}}
malware_permissions         {top_malware_permissions[], other_abused_permissions[], total_malware_permissions: 25,
                             total_other_permissions: 44}
certificate_analysis        {certificate_info: newline-joined human text (signed?, v1-v4 flags, subject, alg,
                             validity, issuer, serial, hash alg, md5/sha1/sha256/sha512, pubkey alg/bits/fingerprint),
                             certificate_findings: [[severity, description, title]],
                             certificate_summary: {high, warning, info}}
manifest_analysis           {manifest_findings: [{rule, title (HTML), severity, description, name, component[]}],
                             manifest_summary: {high, warning, info (always 0, bug), suppressed}}
network_security            {network_findings: [{scope[], description, severity}],
                             network_summary: {high, warning, info, secure}}
binary_analysis             [ {name: rel path of .so,
                               nx{is_nx, severity, description}, pie{is_pie, ...}, stack_canary{has_canary, ...},
                               relocation_readonly{relro, ...}, rpath{rpath, ...}, runpath{runpath, ...},
                               fortify{is_fortified, ...}, symbol{is_stripped, ...}} ]
file_analysis               [{finding, files[]}] hardcoded cert/keystore files (SO scans: [symbol names])
android_api                 {api_rule_id: {files: {rel_path: "lines"}, metadata: {description, severity}}}
code_analysis               {findings: {rule_id: {files: {rel_path: "l1,l2"}, metadata: {cvss, cwe, owasp-mobile,
                             masvs, ref, description, severity}}},
                             summary: {high, warning, info, secure, suppressed}}
                             (JAR/AAR add synthetic `aar_class_obfuscation`)
niap_analysis               {requirement_id: {choice, description, class}} (empty unless NIAP enabled)
permission_mapping          {permission: {rel_path: "lines"}}
urls                        [{urls[], path}] per source file / resource / .so
domains                     {domain: {bad: 'yes'|'no', geolocation: IP2Location record dict | null, ofac: bool,
                             [domain_or_url, ip, desc] when bad}}
emails                      [{emails[], path}]
strings                     {strings_apk_res: ['"key" : "value"'], strings_so: [{so_path: [str]}],
                             strings_code: [str]}
firebase_urls               [{title, severity, description}]
files                       [str] archive entries
exported_count              {exported_activities, exported_services, exported_receivers, exported_providers}
apkid                       {inner_file: {"<tags>": [descriptions]}}
behaviour                   {rule_id: {files: {rel_path: "lines"}, metadata: {label[], description, severity}}}
trackers                    {detected_trackers: int, total_trackers: int, trackers: [{name, categories, url}]}
playstore_details           google-play-scraper dict (title, score, installs, developer, ..., description) + error
                            flag, or {error: true, description}
secrets                     [str] known-format secrets first, then heuristic ones
logs                        [{timestamp, status, exception}] scan log
sbom                        {sbom_versioned: ["group:name@ver"], sbom_packages: ["a.b.c"]}
average_cvss                float | null (null unless CVSS_SCORE_ENABLED)
appsec                      scorecard: {high[], warning[], info[], secure[], hotspot[] each {title, description,
                             section}, total_trackers, trackers, security_score (0-100), app_name, file_name, hash,
                             version_name}
virus_total                 null | {response_code, verbose_msg, positives, total, md5, sha1, sha256, scan_date,
                             permalink, resource, scan_id, scans: {engine: {detected, result, version, update}}}
                             | short status message dict
base_url / dwd_dir / host_os / timestamp   report_json plumbing (local paths, OS, scan time)
dynamic_analysis_done       bool (scan API response only)
```

### D.2 iOS (IPA; source zip / dylib / .a fill the same keys, some empty)

```
version / title / file_name / size / md5 / sha1 / sha256   as Android
app_name                    CFBundleDisplayName or CFBundleName (or .app dir name)
app_type                    'Swift' | 'Objective C' | 'Dylib' | 'A' | source type ('Swift', 'Objective-C',
                            'Swift, Objective-C', 'No Code')
build                       CFBundleVersion
app_version                 CFBundleShortVersionString
sdk_name                    DTSDKName
platform                    DTPlatformVersion
min_os_version              MinimumOSVersion
bundle_id                   resolved bundle id
bundle_url_types            CFBundleURLTypes (list of dicts)
bundle_supported_platforms  CFBundleSupportedPlatforms
icon_path                   extracted icon
info_plist                  Info.plist as XML text
binary_info                 {endian, bit: '32-bit'|'64-bit', arch, subarch}
permissions                 {NS...UsageDescription: {info, status: normal|dangerous, description: app string}}
ats_analysis                {ats_findings: [{issue, severity, description}], ats_summary: {high, warning, info, secure}}
binary_analysis             {findings: {rule description: {detailed_desc, severity, cvss, cwe, owasp-mobile, masvs}},
                             summary: {high, warning, info, secure, suppressed}}
macho_analysis              {name, nx{has_nx,...}, pie{has_pie,...}, stack_canary{has_canary,...}, arc{has_arc,...},
                             rpath{has_rpath,...}, code_signature{has_code_signature,...},
                             encrypted{is_encrypted,...}, symbol{is_stripped,...}} (each with severity, description)
dylib_analysis              [macho_analysis-shaped dicts] for *.dylib (and *.o in .a)
framework_analysis          [macho_analysis-shaped dicts] for X.framework/X
ios_api                     {rule_id: {files, metadata{description, severity}}} (source zips only)
code_analysis               {findings: {rule_id: {files, metadata}}, summary} (source zips only)
file_analysis               [{issue: 'SQLite Files'|'Plist Files'|'Certificate/Key Files Hardcoded inside the App.',
                             files: [{file_path, type, hash}]}] (dylib/.a: [symbol names])
libraries                   [ "name (compatibility version: x, current version: y)" ]
files                       [str] relative file list
urls / emails               [{urls[]|emails[], path}]
domains                     as Android
strings                     [str] binary strings (+ dylib/framework strings)
firebase_urls               as Android
appstore_details            iTunes lookup subset {features, icon, developer_id, developer, developer_url,
                             developer_website, supported_devices, title, app_id, category, description, price,
                             itunes_url, score, error} or {error: true}
secrets                     [str]
trackers                    as Android (domain-based only)
logs                        scan log
average_cvss / appsec / virus_total / base_url / dwd_dir / host_os / timestamp   as Android
```

---

## E. Every place the core makes network requests

Static and malware analyzers (all go through `upstream_proxy()` settings):

| # | Where | Request | When |
|---|---|---|---|
| 1 | `StaticAnalyzer/views/android/manifest_analysis.py::_check_url` | `GET http(s)://<host>[:80\|443]/.well-known/assetlinks.json` (http also retried as https), SSRF-guarded `safe_request`, 5 s | every BROWSABLE activity with http(s) scheme + host |
| 2 | `StaticAnalyzer/views/android/playstore.py::get_app_details` | `GET https://play.google.com` probe, then `google_play_scraper.app(pkg)` (play.google.com scraping) | every APK / Android source scan |
| 3 | `.../android/playstore.py::app_search` | `GET https://api.appmonsta.com/v1/stores/android/details/<pkg>.json?country=US` (basic auth) | fallback, only if `APPMONSTA_API` set |
| 4 | `StaticAnalyzer/views/ios/appstore.py::app_search` | `GET https://itunes.apple.com/lookup?bundleId=<id>&country=us&entity=software` | every IPA / iOS source scan |
| 5 | `StaticAnalyzer/views/common/firebase.py::open_firebase` | `GET https://<x>.firebaseio.com/.json` (SSRF-guarded) | per Firebase DB URL found |
| 6 | `.../common/firebase.py::firebase_remote_config` | `POST https://firebaseremoteconfig.googleapis.com/v1/projects/<num>/namespaces/firebase:fetch?key=<google_api_key>` | when `google_api_key` + `google_app_id` resource strings exist |
| 7 | `MalwareAnalyzer/views/Trackers.py::_update_tracker_db` | `GET https://reports.exodus-privacy.eu.org/api/trackers` (overwrites local DB if hash differs) | on every `Trackers()` construction (each scan) when online |
| 8 | `MalwareAnalyzer/views/MalwareDomainCheck.py::update_maltrail_db` | `GET https://github.com/stamparm/trails/releases/latest/download/maltrail-malware-domains.txt` (120 s) | every domain check when online |
| 9 | `.../MalwareDomainCheck.py::gelocation` -> `MobSF/security.py::resolve_public_ip` | DNS resolution (`socket.getaddrinfo`) of every extracted domain | every scan with URLs |
| 10 | `MobSF/utils.py::is_internet_available` | `GET https://www.google.com`, fallback `https://www.baidu.com/` (5 s) | before 7 and 8 |
| 11 | `MalwareAnalyzer/views/VirusTotal.py` | `GET/POST https://www.virustotal.com/api/v3/files[/<md5>\|/upload_url]`, analysis polling | only if `VT_ENABLED` (+ upload if `VT_UPLOAD`) |
| 12 | `tldextract.extract` (used by `Trackers.get_trackers_domains_or_deps`) | may fetch the Public Suffix List from publicsuffix.org / GitHub on first use (cached, snapshot fallback) | first domain-based tracker check |
| 13 | `MobSF/tools_download.py::install_jadx` | `https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip` | first run (bootstrap) |
| 14 | `MobSF/utils.py::check_update` | `HEAD https://github.com/MobSF/Mobile-Security-Framework-MobSF/releases/latest` | startup |
| 15 | `MobSF/views/apk_downloader.py` (view, out of scope) | APKPure / apktada / apkplz downloads | user-triggered APK download |

No network is used by apktool, jadx, baksmali, bundletool, apksigner, APKiD, LIEF or the SAST engine (libsast can
fetch rules from http(s) URLs, but MobSF passes local paths).

Dynamic analyzer (see B.5): GitHub Frida releases API + asset download, Corellium REST
(`<CORELLIUM_API_DOMAIN>/api/v1/...`), Corellium SSH bastion and device SSH (paramiko), `https://cydia.akemi.ai/` apt
repo via the device, local httptools control (`http://127.0.0.1:<port>/kill`), plus reuse of rows 7-10.

Rust recommendation: put every row behind an explicit `NetworkPolicy` (offline by default) and make DB refreshes
(rows 7, 8, 12) separate maintenance calls, so scans become deterministic.

---

## F. Proposed porting order

Suggested module layout inside `msec` (split into crates only if compile times demand it): `core` (report types,
severity, config, progress callback), `archive`, `axml`, `android`, `sast`, `binary`, `secrets`, `trackers`, `ios`,
`malware`, `net` (optional SSRF-safe client), `dynamic`.

**Phase 0 - foundation (S-M)**

- Typed `Report` structs with serde that emit the exact key tree in D. Keep the legacy shapes, e.g. tuples as
  arrays and `"1,2,3"` line strings, behind a compatibility serializer.
- Safe unzip: zip-slip, reserved-name `_conflict_`, encrypted-entry skip, size caps, tolerant parsing of malformed
  headers.
- SHA-1/SHA-256/MD5 hashing and magic-based input detection.
- Regex compatibility layer: try `regex`, fall back to `fancy-regex`, and document the Python semantics.
- Golden-test harness: run upstream MobSF v4.5.3 (its Docker image, outside this crate) over a fixed corpus, store
  the JSON reports, and diff them section by section against the Rust output.

**Phase 1 - Android without a decompiler (first consumer needs)**

1. **AXML + ARSC decoder** (L). This is the prerequisite for everything manifest-related and replaces both apktool
   and androguard. It must reproduce apktool-style names: `@xml/network_security_config`, protectionLevel names,
   and booleans as `true`/`false`.
2. **Manifest extraction + permission KB** (S): components, SDKs, versions, main activity; `DVM_PERMISSIONS` lookup
   gives `permissions`. `malware_permissions` is trivial, so add it here.
3. **Manifest analysis** (M): the rule table, the protectionLevel x export decision table, browsable activities.
   The assetlinks check sits behind the network policy.
4. **Network security config** (S).
5. **Certificate / signature analysis** (M-L):
   - v1 PKCS#7, the APK Signing Block (v2/v3/v3.1), X.509 details, fingerprints and the five findings.
   - Hardcoded cert/keystore files.
   - Decide whether "vN: true" means present or cryptographically verified. MobSF uses apksigner's verify result.
6. **ELF checksec + strings + symbols** (S-M) with `goblin`/`object`.

**Phase 2 - code rules, secrets, trackers**

7. **SAST engine** (M):
   - Pattern semantics, comment stripping, line computation and the formatting in C.0, plus standards expansion.
   - Rule sets: `android_rules`, `android_apis`, permission mapping, `behaviour_rules`; NIAP choice matcher (S,
     optional).
   - Input is decompiled Java from a pluggable `Decompiler` trait (jadx subprocess first). The `.java`/`.kt` of
     source zips need no decompiler.
8. **Strings / secrets / entropy / URL+email extraction** (S): ARSC string resources, `.so` strings, code string
   literals, the 22 known-secret patterns, Firebase credential detection. The Firebase network probes go behind the
   network policy.
9. **Trackers** (S-M): native DEX class enumeration plus Exodus `code_signature` matching; domain-based matching
   with a PSL crate.
10. **SBOM** (S) and **report assembly** (S-M): suppression filtering as a pure function, `appsec` scorecard,
    `average_cvss`.

**Phase 3 - iOS**

11. IPA extraction + `Payload/*.app` detection; Info.plist / permissions / ATS / bundle id (S).
12. Mach-O checksec + `binary_info` + libraries for the main binary, dylibs, frameworks and `.a` members (M).
13. ObjC/Swift metadata extraction to replace class-dump/jtool, plus `IPA_RULES` (L). Until then, symbols alone
    give partial coverage of the 10 rules.
14. iOS source zips through the SAST engine with the ObjC/Swift/API rule files (S once the engine exists); strings,
    secrets and URLs (S).

**Phase 4 - malware analyzer**

15. Domain extraction + maltrail + malwaredomainlist matching (S); IP2Location BIN reader + DNS with the public-IP
    filter (M); OFAC flag (S).
16. APKiD via `yara-x` (M). First validate that all 360 APKiD rules compile under yara-x, including the `dex`
    module.
17. VirusTotal client and Play Store / App Store lookups (S/M, optional features).

**Phase 5 - remaining static inputs**: XAPK/APKS (S), JAR/AAR/SO entry points (S), AAB (L natively: protobuf
manifest; or wrap bundletool), icons incl. vector drawable -> SVG and CgBI PNG fix (M), Windows APPX (skip).

**Phase 6 - dynamic (last)**:

- Port the pure post-processing parsers first: Frida API-monitor, iOS dump JSON, traffic URL/domain extraction,
  TLS-test evaluation.
- Then the adb wrapper + `frida-rust` sessions, with the Frida JS scripts shipped unchanged as assets.
- Then proxy/CA, the TLS test state machine, the Corellium REST client, SSH tunnelling (`russh`) and the device
  path.

**Cross-cutting risks**

- **Licensing:**
  - MobSF is GPL-3.0-only. Translating its Python logic, or shipping its rule YAMLs, the manifest templates or the
    permission tables, makes the crate a GPL-3.0 derivative. A permissively licensed crate needs a clean-room
    design and independently authored rules.
  - `dvm_permissions.py` carries an androguard LGPL header.
  - APKiD rules are GPL-3.0 or commercial; apksigtool is AGPL-3.0+.
  - The Maltrail data licence restricts commercial redistribution, and the IP2Location LITE terms require
    attribution.
- **Java dependency:** code rules on APKs need jadx, which requires a JRE. There is no Rust Java decompiler. Running
  rules on smali would mean rewriting the rules.
- **Regex dialect and Unicode:** see B.0.
- **Line-number parity quirks:** see C.0.
- **Non-determinism:** network DB refreshes, use of the host `strings`/`nm`/`objdump`, NIAP set ordering.

---

## G. External dependencies and licences

| Dependency | Version (poetry.lock) | Licence | Used for | Rust replacement |
|---|---|---|---|---|
| libsast | 3.1.8 | LGPL-3.0-or-later | pattern + choice matcher, standards maps | own engine (`regex`/`fancy-regex`, `rayon`, `serde_yaml`-family) |
| androguard (vendored, master `04a5703b`, ~4.1.2+) | vendored | Apache-2.0 (`dvm_permissions.py` header says LGPL-3) | APK/AXML/ARSC/signature parsing | own AXML/ARSC + RustCrypto `cms`/`x509-cert`/`der` |
| apkInspector (vendored v1.3.2 parts) | vendored | Apache-2.0 | tolerant ZIP parsing | own tolerant ZIP reader or `zip` + fallbacks |
| apkid | 3.1.0 (yara-python-dex) | GPL-3.0 or commercial | packer/obfuscator/anti-* detection | `yara-x` (BSD-3) with recompiled APKiD rules |
| lief | 0.17.6 | Apache-2.0 | ELF/Mach-O parsing | `goblin` (MIT) / `object` (Apache-2.0/MIT) |
| macholib | 1.16.4 | MIT | Mach-O header info | `goblin` |
| apksigtool + apksigcopier | 0.1.0 / 1.1.1 | AGPL-3.0+ / GPL-3.0+ | fallback signature parsing | native APK Signing Block parser |
| asn1crypto, cryptography | 1.5.1 / 45.0.7 | MIT / Apache-2.0 or BSD | X.509, public keys | `x509-cert`, `der`, `spki`, `rsa`, `p256`/`p384` |
| IP2Location (python) | 8.11.0 | MIT | BIN DB reader | small native reader |
| tldextract | 5.3.2 | BSD-3-Clause | registrable domain | `psl` / `publicsuffix` |
| google-play-scraper | 1.2.7 | MIT | Play Store metadata | optional `reqwest` scraper |
| openstep-parser | 2.0.3 | MIT/BSD-2 (metadata vs LICENSE differ) | `.pbxproj` | small native parser |
| arpy | 2.4.0 | BSD-2-Clause | `.a` archives | `ar` crate |
| defusedxml, bs4, lxml | 0.7.1 / - / 6.1.3 | PSF / MIT / BSD-3 | XML parsing | `roxmltree` / `quick-xml` |
| PyYAML | - | MIT | rule loading | `serde_yaml` or a maintained fork |
| svgutils | 0.3.4 | MIT | icon SVG composition | optional |
| frida / frida-tools | 17.18.0 / 14.10.4 | wxWindows Library Licence 3.1 | dynamic | `frida-rust` |
| http-tools (mitmproxy 12.1.2) | 6.0.0 | LGPL (classifier 3+, file 2.1) / MIT | dynamic proxy | shell out or `hudsucker` |
| paramiko | 3.5.1 | LGPL-2.1 | Corellium/device SSH | `russh` / `ssh2` |
| jadx | 1.5.0 (downloaded) | Apache-2.0 | Java decompilation | keep external |
| apktool | 3.0.3 jar | Apache-2.0 | manifest/res decode | replaced by native AXML/ARSC |
| baksmali | 3.0.8 jar | BSD-3-style | class listing (trackers), smali for UI | native DEX reader |
| bundletool | 1.17.2 jar | Apache-2.0 | AAB -> universal APK | keep external or native protobuf |
| apksigner | jar | Apache-2.0 | signature scheme verification | native verifier |
| vd2svg | 0.4.4 jar | Apache-2.0 | vector drawable -> SVG | small native converter |
| class-dump / class-dump-swift | macOS binaries | GPL-2.0+ (class-dump) | ObjC metadata | native ObjC metadata parser |
| jtool (v1) | ELF binary | proprietary freeware | ObjC metadata on Linux | native parser |
| CgbiPngFix | Go binaries | BSD-3-Clause | iOS CgBI PNG repair | native (`flate2` + `png`) |
| MobSF | 4.5.3 | GPL-3.0-only | everything above, incl. all rule YAMLs and KB tables | see licensing risk in F |

---

## H. Behaviours and quirks worth deciding on before porting

1. `suppression.py::process_suppression_manifest` has `elif ['severity'] == INFO`, which is never true, so
   `manifest_summary.info` is always 0.
2. Manifest `protectionLevel` decoding only maps exact `0x00000000`-`0x00000003` (androguard path). The apktool path
   yields names, and combined flags such as `signature|privileged` fall through every branch, so the component gets
   no finding.
3. ELF PIE vs DSO is decided by the presence of `DT_DEBUG` on `ET_DYN` objects (a heuristic). Dart/Flutter libraries
   are treated as canary-present and RELRO "Not Applicable".
4. Mach-O stack-canary detection requires **both** `___stack_chk_fail` and `___stack_chk_guard` imports.
5. String extraction depends on the host. MobSF uses the OS `strings` when present (min length 4) and otherwise a
   Python scanner (min length 6, results wrapped in quotes), so reports differ across hosts.
6. `dex_2_smali` runs in background daemon threads and is unused by the analysis. Trackers still need baksmali
   `list classes`.
7. IPA processing mutates the extracted tree: `+` becomes `x` in file names and binary plists are rewritten as XML.
8. Exodus and Maltrail databases silently self-update during scans, so results drift over time.
9. The NIAP choice matcher result depends on file iteration order (last file wins).
10. Manifest finding titles and descriptions embed HTML (`<strong>`, `<br>`, `</br>`). A Rust port should keep
    structured fields and render HTML only in a compatibility layer.
11. `certificate_info` is free text that later checks regex-search (`CN=Android Debug`, `Hash Algorithm: sha1`).
    Keep structured cert data and derive both the text and the findings from it.
12. `targetSdk` prefers aapt2 badging over the manifest. Without aapt2 it falls back to the manifest
    `targetSdkVersion`, then `minSdkVersion`.
13. `get_avg_cvss` is passed the wrapper dict `{findings, summary}` instead of `findings` in several paths:
    JAR/AAR (`jar_aar.py:207`), the Android JSON/PDF report (`pdf.py:168`), the IPA and iOS-source scans (`ipa.py:271,358`) and
    the iOS JSON/PDF report (`pdf.py:185-189`). There it never finds a `cvss` value and returns 0 when CVSS is enabled. Only
    the APK and Android-source scan paths (`apk.py:251,368`) pass `findings` correctly. The setting is off by
    default, so the value is normally `null`.
