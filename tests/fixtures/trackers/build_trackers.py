#!/usr/bin/env python3
"""Builds the tracker fixtures and records what MobSF's own tracker code reports for them.

Outputs, in this directory:
- trackers.apk: an app whose DEX code holds classes in the packages of five trackers (Facebook
  Analytics, Adjust, AppsFlyer, Google Firebase Analytics, Google AdMob) and one look-alike
  package that is no tracker (com.adjusted);
- trackers.ipa: the iOS fixture app (../ios/ipa/fixture.ipa) with endpoints.json naming tracker
  and other hosts, and a privacy manifest declaring one tracking domain (app.adjust.com);
- classes.txt: the class descriptors AOSP's dexdump lists in trackers.apk's classes.dex (as
  baksmali, which MobSF runs, lists them);
- mobsf-verdicts.txt: the trackers MobSF v4.5.3's `Trackers.detect_trackers_in_list` finds in
  those classes, and in the hosts of the URLs in endpoints.json (taken with MobSF's URL_REGEX and
  Python's urlparse), with the Exodus snapshot msec ships.

Needs ANDROID_HOME (or the default macOS SDK location) with build-tools 37.0.0 and platform
android-37.0, a JDK (javac and java on PATH, or JAVA_HOME), MOBSF_SRC (a MobSF v4.5.3 checkout)
and EXODUS_TRACKERS (the trackers.json snapshot src/trackers/generated/exodus.rs was generated
from; its SHA-256 is checked against that file's header).
"""

from __future__ import annotations

import ast
import hashlib
import io
import itertools
import json
import logging
import os
import plistlib
import re
import subprocess
import tempfile
import zipfile
from collections import namedtuple
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
SDK = Path(os.environ.get("ANDROID_HOME", Path.home() / "Library/Android/sdk"))
TOOLS = SDK / "build-tools/37.0.0"
PLATFORM = SDK / "platforms/android-37.0/android.jar"
DATE = (2026, 1, 1, 0, 0, 0)
BUNDLE = "Payload/Fixture.app/"

CLASSES = [
    "com.facebook.appevents.AppEventsLogger",
    "com.adjust.sdk.Adjust",
    "com.appsflyer.AppsFlyerLib",
    "com.google.firebase.analytics.FirebaseAnalytics",
    "com.google.android.gms.ads.AdView",
    "com.adjusted.Thing",
    "dev.appchk.fixture.trackers.Main",
]
ENDPOINTS = {
    "analytics": "https://api.mixpanel.com/track",
    "attribution": "https://app.adjust.com/session",
    "social": "https://graph.facebook.com/v19.0/me",
    "backend": "https://api.example.com/v1",
    "docs": "https://developer.apple.com/documentation",
}
DECLARED_TRACKING_DOMAINS = ["app.adjust.com"]


def run(*command, **options):
    return subprocess.run([str(part) for part in command], check=True, **options)


def build_apk(work: Path) -> tuple[bytes, list[str]]:
    sources = work / "java"
    for name in CLASSES:
        package, _, simple = name.rpartition(".")
        directory = sources / package.replace(".", "/")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{simple}.java").write_text(
            f"package {package};\n\npublic final class {simple} {{\n"
            "    public static String name() { return \"" + simple + "\"; }\n}\n"
        )
    classes = work / "classes"
    run("javac", "--release", "8", "-nowarn", "-Xlint:-options", "-d", classes, *sorted(sources.rglob("*.java")))
    dex = work / "dex"
    dex.mkdir()
    run(
        "java", "-cp", TOOLS / "lib/d8.jar", "com.android.tools.r8.D8", "--release", "--lib", PLATFORM,
        "--min-api", "24", "--output", dex, *sorted(classes.rglob("*.class")),
    )
    manifest = work / "AndroidManifest.xml"
    manifest.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    package="dev.appchk.fixture.trackers">\n'
        '    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />\n'
        "    <application />\n"
        "</manifest>\n"
    )
    run(TOOLS / "aapt2", "link", "-I", PLATFORM, "--manifest", manifest, "-o", work / "base.apk")
    dexdump = run(TOOLS / "dexdump", "-n", dex / "classes.dex", capture_output=True, text=True).stdout
    descriptors = sorted(re.findall(r"Class descriptor\s+: '([^']+)'", dexdump))
    entries: dict[str, bytes] = {}
    with zipfile.ZipFile(work / "base.apk") as base:
        for info in base.infolist():
            entries[info.filename] = base.read(info)
    entries["classes.dex"] = (dex / "classes.dex").read_bytes()
    output = work / "trackers.apk"
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(entries, key=lambda entry: (entry != "AndroidManifest.xml", entry)):
            info = zipfile.ZipInfo(name, date_time=DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, entries[name])
    return output.read_bytes(), descriptors


def build_ipa(work: Path) -> bytes:
    entries: dict[str, bytes] = {}
    with zipfile.ZipFile(ROOT / "tests/fixtures/ios/ipa/fixture.ipa") as base:
        for info in base.infolist():
            if not info.is_dir():
                entries[info.filename] = base.read(info)
    manifest = plistlib.loads(entries[BUNDLE + "PrivacyInfo.xcprivacy"])
    manifest["NSPrivacyTracking"] = True
    manifest["NSPrivacyTrackingDomains"] = DECLARED_TRACKING_DOMAINS
    entries[BUNDLE + "PrivacyInfo.xcprivacy"] = plistlib.dumps(manifest, fmt=plistlib.FMT_XML)
    entries[BUNDLE + "endpoints.json"] = (json.dumps(ENDPOINTS, indent=2) + "\n").encode()
    output = work / "trackers.ipa"
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, entries[name])
    return output.read_bytes()


def mobsf_trackers(source: Path, database: Path):
    """MobSF's Trackers class with only its matching methods, loaded from its own file."""
    tree = ast.parse((source / "mobsf/MalwareAnalyzer/views/Trackers.py").read_text())
    trackers_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Trackers")
    keep = {"_compile_signatures", "load_trackers_signatures", "detect_trackers_in_list"}
    trackers_class.body = [node for node in trackers_class.body if isinstance(node, ast.FunctionDef) and node.name in keep]
    namespace = {
        "re": re, "io": io, "itertools": itertools, "json": json, "namedtuple": namedtuple,
        "logger": logging.getLogger("mobsf"),
    }
    exec(compile(ast.Module(body=[trackers_class], type_ignores=[]), "Trackers.py", "exec"), namespace)
    instance = object.__new__(namespace["Trackers"])
    instance.tracker_db = str(database)
    instance.signatures = None
    return instance


def check_snapshot(database: Path) -> None:
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    generated = (ROOT / "src/trackers/generated/exodus.rs").read_text()
    if digest not in generated:
        raise SystemExit(f"{database} is not the snapshot exodus.rs was generated from")


def main() -> None:
    mobsf = Path(os.environ["MOBSF_SRC"])
    database = Path(os.environ["EXODUS_TRACKERS"])
    check_snapshot(database)
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        apk, descriptors = build_apk(work)
        (HERE / "trackers.apk").write_bytes(apk)
        (HERE / "trackers.ipa").write_bytes(build_ipa(work))
    (HERE / "classes.txt").write_text("\n".join(descriptors) + "\n")
    url_regex = re.compile(
        r"((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%'{}-]+)",
        re.UNICODE | re.IGNORECASE,
    )
    text = json.dumps(ENDPOINTS, indent=2)
    hosts = sorted({urlparse(url).hostname for url in url_regex.findall(text) if urlparse(url).hostname})
    trackers = mobsf_trackers(mobsf, database)
    code = sorted(tracker.name for tracker in trackers.detect_trackers_in_list(descriptors))
    network = sorted(tracker.name for tracker in trackers.detect_trackers_in_list(hosts, network=True))
    (HERE / "mobsf-verdicts.txt").write_text(
        f"apk-code\t{'|'.join(code)}\nipa-hosts\t{'|'.join(hosts)}\nipa-network\t{'|'.join(network)}\n"
    )
    print(f"wrote trackers.apk, trackers.ipa, classes.txt, mobsf-verdicts.txt in {HERE}")


if __name__ == "__main__":
    main()
