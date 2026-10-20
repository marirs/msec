#!/usr/bin/env python3
"""Builds the secrets fixtures and records what MobSF and gitleaks report for each secret.

Outputs, in this directory:
- units.txt: every fixture value, where it is placed, and under which key (masked, see
  `mask`, so no token appears in a text file, even to scanners that decode Base64);
- mobsf-verdicts.txt: what MobSF v4.5.3's own code reports for each value
  (`secret_detection.detect_known_secrets`, `shared_func.is_secret_key`, `entropy.get_entropies`);
- gitleaks-verdicts.txt: the rules gitleaks 8.30.1 reports for each value or file
  (`gitleaks dir --max-decode-depth 0`: msec does not port gitleaks' decoding yet);
- secrets.apk: an app holding the values in its resources, DEX code and static values, a native
  library, assets and a raw resource;
- secrets.ipa: the iOS fixture app (../ios/ipa/fixture.ipa) with the iOS values added: two
  property lists (Google's GoogleService-Info.plist in XML, an app Config.plist in binary), a
  JSON file, and a library built with Xcode's clang whose C strings hold more.

Every secret is fake, generated from a fixed seed; token prefixes are split in this file, text
outputs hold values masked, and every entry of secrets.apk is deflated, so secret scanners and
push protection see no token in the repository.

Needs ANDROID_HOME (or the default macOS SDK location) with build-tools 37.0.0 and platform
android-37.0, a JDK (javac and java on PATH, or JAVA_HOME), MOBSF_SRC (a MobSF v4.5.3 checkout,
for its secret detection code), gitleaks 8.30.1 on PATH, and Xcode (an iOS SDK) for the IPA.
"""

from __future__ import annotations

import ast
import base64
import json
import os
import plistlib
import random
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "android"))
import make_elf_fixtures  # noqa: E402

SDK = Path(os.environ.get("ANDROID_HOME", Path.home() / "Library/Android/sdk"))
TOOLS = SDK / "build-tools/37.0.0"
PLATFORM = SDK / "platforms/android-37.0/android.jar"
PACKAGE = "dev.appchk.fixture.secrets"
NATIVE_LIBRARY = "lib/arm64-v8a/libsecrets.so"
DATE = (2026, 1, 1, 0, 0, 0)

random_source = random.Random(20261020)
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = UPPER.lower()
DIGITS = "0123456789"
ALNUM = UPPER + LOWER + DIGITS
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "_-"


def pick(alphabet: str, length: int) -> str:
    return "".join(random_source.choice(alphabet) for _ in range(length))


def join(*parts: str) -> str:
    """Prefixes are written in pieces so no token appears whole in this file."""
    return "".join(parts)


# (name, placement, key, value). Placements: resource (a string resource named `key`), code (a
# literal returned by a method of its own class), static (a constant no code loads: a DEX static
# value), native (the native library's .rodata), file (a whole text file at path `key`).
UNITS: list[tuple[str, str, str, str]] = [
    ("google_api_key", "resource", "google_api_key", join("AI", "za", pick(URLSAFE, 35))),
    ("aws_secret", "resource", "aws_secret_access_key", pick(ALNUM + "+/", 40)),
    ("build_token", "resource", "build_token", join("gh", "p_", pick(ALNUM, 36))),
    ("payments", "resource", "payments_backend", join("sk", "_live_", pick(ALNUM, 24))),
    ("twilio", "resource", "twilio_sid", join("S", "K", pick(HEX, 32))),
    ("hint_password", "resource", "hint_password", "Enter your password"),
    ("app_name", "resource", "app_name", "Secrets Fixture"),
    ("slack_bot", "code", "", join("xo", "xb-", pick(DIGITS, 12), "-", pick(DIGITS, 13), "-", pick(ALNUM, 24))),
    ("sendgrid", "code", "", join("S", "G.", pick(URLSAFE, 22), ".", pick(URLSAFE, 43))),
    ("openai", "code", "", join("sk-", "proj-", pick(URLSAFE, 74), "T3Blbk", "FJ", pick(URLSAFE, 74))),
    ("anthropic", "code", "", join("sk-", "ant-", "api03-", pick(URLSAFE, 93), "AA")),
    ("hugging_face", "code", "", join("h", "f_", pick(UPPER + LOWER, 34))),
    ("aws_key_id", "code", "", join("AK", "IA", pick(UPPER + "234567", 16))),
    ("jwt", "code", "", join("ey", "JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.", "ey", "JzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFub24ifQ.", pick(URLSAFE, 43))),
    ("npm", "code", "", join("np", "m_", pick(LOWER + DIGITS, 36))),
    ("age", "code", "", join("AGE-", "SECRET-KEY-1", pick("QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L", 58))),
    ("entropy_base64", "code", "", pick(ALNUM + "+/", 40)),
    ("entropy_hex", "code", "", pick(HEX, 40)),
    ("endpoint", "code", "", "https://api.example.com/v1/items"),
    ("class_name", "code", "", "com.example.app.ui.MainActivity"),
    ("doppler", "static", "", join("dp", ".pt.", pick(ALNUM, 43))),
    ("brevo", "native", "", join("xkey", "sib-", pick(HEX, 64), "-", pick(ALNUM, 16))),
    ("sentry", "native", "", join("sntr", "yu_", pick(HEX, 64))),
    ("shopify", "native", "", join("shp", "at_", pick(HEX, 32))),
    ("square", "native", "", join("sq0", "atp-", pick(URLSAFE, 22))),
    ("digitalocean", "native", "", join("do", "p_v1_", pick(HEX, 64))),
    ("lwa_secret", "native", "", join("amzn1", ".oa2-cs.v1.", pick(HEX, 64))),
    ("lwa_access", "native", "", join("At", "za|", pick(URLSAFE, 40))),
    ("lwa_refresh", "native", "", join("At", "zr|", pick(URLSAFE, 40))),
    ("native_entropy", "native", "", pick(ALNUM + "+/", 32)),
    ("native_text", "native", "", "libsecrets fixture version 1.0"),
]

GITHUB_ALLOWED = join("gh", "p_", pick(ALNUM, 36))
AWS_EXAMPLE = join("AK", "IA", "IOSFODNN7", "EXAMPLE")
PEM_BODY = "\n".join(pick(ALNUM + "+/", 64) for _ in range(6))
FILES: list[tuple[str, str]] = [
    (
        "assets/config.json",
        "{\n"
        f'  "api_secret": "{pick(LOWER + DIGITS, 12)}{pick(DIGITS, 4)}{pick(LOWER, 8)}",\n'
        f'  "algolia_api_key": "{pick(LOWER + DIGITS, 32)}",\n'
        f'  "mapbox_token": "{join("p", "k.")}{pick(LOWER + DIGITS, 60)}.{pick(LOWER + DIGITS, 22)}",\n'
        f'  "heroku_api_key": "{pick(HEX, 8)}-{pick(HEX, 4)}-{pick(HEX, 4)}-{pick(HEX, 4)}-{pick(HEX, 12)}",\n'
        f'  "slack_webhook": "{join("https://hooks.", "slack.com/services/")}T{pick(UPPER + DIGITS, 10)}/B{pick(UPPER + DIGITS, 10)}/{pick(ALNUM, 24)}",\n'
        f'  "telegram_bot_token": "{pick(DIGITS, 9)}:A{pick(LOWER + DIGITS, 34)}",\n'
        f'  "deploy": "{join("gl", "pat-")}{pick(URLSAFE, 20)}",\n'
        f'  "documented_example": "{AWS_EXAMPLE}",\n'
        f'  "reviewed": "{GITHUB_ALLOWED}", "note": "gitleaks:allow"\n'
        "}\n",
    ),
    (
        "assets/keys/server.pem",
        join("-----BEGIN RSA ", "PRIVATE KEY-----\n") + PEM_BODY + join("\n-----END RSA ", "PRIVATE KEY-----\n"),
    ),
    (
        "res/raw/notes.txt",
        "Release notes\n"
        f"mapbox secret: {join('s', 'k.')}{pick(URLSAFE, 60)}.{pick(URLSAFE, 22)}\n"
        f"pypi: {join('pypi-', 'AgEIcHlwaS5vcmc')}{pick(URLSAFE, 60)}\n"
        f"1password: {join('A3', '-')}{pick(UPPER + DIGITS, 6)}-{pick(UPPER + DIGITS, 11)}-{pick(UPPER + DIGITS, 5)}-{pick(UPPER + DIGITS, 5)}-{pick(UPPER + DIGITS, 5)}\n"
        f"heroku: {join('HRKU', '-AA')}{pick(URLSAFE, 58)}\n",
    ),
]
KEY_STORE = "assets/certs/client.p12"

# The iOS values draw on their own seed, so adding them left the APK's values unchanged.
ios_source = random.Random(20261021)
BUNDLE = "Payload/Fixture.app/"
IOS_LIBRARY = BUNDLE + "Frameworks/libsecrets.dylib"


def ios_pick(alphabet: str, length: int) -> str:
    return "".join(ios_source.choice(alphabet) for _ in range(length))


# iOS placements: plist (key: `<file>:<key path>`, the value of a string in that property list),
# macho (a C string of libsecrets.dylib); and IOS_FILES, whole text files in the bundle.
IOS_UNITS: list[tuple[str, str, str, str]] = [
    ("ios_google_api_key", "plist", "GoogleService-Info.plist:API_KEY", join("AI", "za", ios_pick(URLSAFE, 35))),
    ("ios_client_id", "plist", "GoogleService-Info.plist:CLIENT_ID", f"{ios_pick(DIGITS, 12)}-{ios_pick(LOWER + DIGITS, 32)}.apps.googleusercontent.com"),
    ("ios_database", "plist", "GoogleService-Info.plist:DATABASE_URL", "https://fixture-default-rtdb.firebaseio.com"),
    ("ios_api_secret", "plist", "Config.plist:ApiSecret", ios_pick(ALNUM, 32)),
    ("ios_stripe", "plist", "Config.plist:Endpoints/Payments", join("sk", "_live_", ios_pick(ALNUM, 24))),
    ("ios_webhook", "plist", "Config.plist:Endpoints/SlackWebhook", join("https://hooks.", "slack.com/services/", "T", ios_pick(UPPER + DIGITS, 9), "/B", ios_pick(UPPER + DIGITS, 9), "/", ios_pick(ALNUM, 24))),
    ("ios_welcome", "plist", "Config.plist:WelcomeText", "Hello there"),
    ("ios_fine_grained", "macho", "", join("github", "_pat_", ios_pick(ALNUM, 22), "_", ios_pick(ALNUM, 59))),
    ("ios_gitlab", "macho", "", join("gl", "pat-", ios_pick(URLSAFE, 20))),
    ("ios_hugging_face", "macho", "", join("h", "f_", ios_pick(UPPER + LOWER, 34))),
    ("ios_entropy", "macho", "", ios_pick(ALNUM + "+/", 36)),
    ("ios_text", "macho", "", "libsecrets for the iOS fixture"),
]
IOS_FILES: list[tuple[str, str]] = [
    (
        BUNDLE + "config.json",
        "{\n"
        f'  "github": "{join("gh", "p_")}{ios_pick(ALNUM, 36)}",\n'
        f'  "aws_access_key_id": "{join("AK", "IA")}{ios_pick(UPPER + "234567", 16)}",\n'
        '  "title": "Fixture"\n'
        "}\n",
    ),
]


def mask(text: str) -> str:
    """Base64 of the text's bytes XORed with 0x5A: decoding the Base64 alone yields no token."""
    return base64.b64encode(bytes(byte ^ 0x5A for byte in text.encode())).decode()


def camel(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("_"))


def java_literal(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def xml_text(text: str) -> str:
    # aapt2 reads a leading @ or ? as a reference and an apostrophe as a quote.
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace("'", "\\'")
    return "\\" + escaped if escaped[:1] in "@?" else escaped


def run(*command: str | Path, **options) -> None:
    subprocess.run([str(part) for part in command], check=True, **options)


def build_apk(work: Path) -> bytes:
    res = work / "res"
    (res / "values").mkdir(parents=True)
    (res / "raw").mkdir(parents=True)
    strings = "".join(
        f'    <string name="{key}">{xml_text(value)}</string>\n'
        for _, placement, key, value in UNITS
        if placement == "resource"
    )
    (res / "values/strings.xml").write_text(f"<resources>\n{strings}</resources>\n")
    for path, text in FILES:
        if path.startswith("res/raw/"):
            (work / path).write_text(text)
    manifest = work / "AndroidManifest.xml"
    manifest.write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        f'    package="{PACKAGE}">\n'
        '    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />\n'
        '    <application android:label="@string/app_name" />\n'
        "</manifest>\n"
    )
    run(TOOLS / "aapt2", "compile", "--dir", res, "-o", work / "res.zip")
    run(TOOLS / "aapt2", "link", "-I", PLATFORM, "--manifest", manifest, "-o", work / "base.apk", work / "res.zip")

    sources = work / "java" / PACKAGE.replace(".", "/")
    sources.mkdir(parents=True)
    for name, placement, _, value in UNITS:
        if placement == "code":
            body = f"    public static String value() {{\n        return {java_literal(value)};\n    }}\n"
        elif placement == "static":
            body = f"    public static final String VALUE = {java_literal(value)};\n"
        else:
            continue
        (sources / f"{camel(name)}.java").write_text(
            f"package {PACKAGE};\n\npublic final class {camel(name)} {{\n{body}}}\n"
        )
    classes = work / "classes"
    run("javac", "--release", "8", "-nowarn", "-Xlint:-options", "-d", classes, *sorted(sources.glob("*.java")))
    dex = work / "dex"
    dex.mkdir()
    run(
        "java", "-cp", TOOLS / "lib/d8.jar", "com.android.tools.r8.D8", "--release", "--lib", PLATFORM,
        "--min-api", "24", "--output", dex, *sorted(classes.rglob("*.class")),
    )
    rodata = b"\0" + b"\0".join(value.encode() for _, placement, _, value in UNITS if placement == "native") + b"\0"
    library = make_elf_fixtures.build(make_elf_fixtures.Library(name="libsecrets.so", extra_sections={".rodata": rodata}))

    entries: dict[str, bytes] = {}
    with zipfile.ZipFile(work / "base.apk") as base:
        for info in base.infolist():
            entries[info.filename] = base.read(info)
    entries["classes.dex"] = (dex / "classes.dex").read_bytes()
    entries[NATIVE_LIBRARY] = library
    for path, text in FILES:
        if path.startswith("assets/"):
            entries[path] = text.encode()
    entries[KEY_STORE] = bytes(random_source.randrange(256) for _ in range(64))
    output = work / "secrets.apk"
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(entries, key=lambda entry: (entry != "AndroidManifest.xml", entry)):
            info = zipfile.ZipInfo(name, date_time=DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, entries[name])
    return output.read_bytes()


def plist_with(values: dict[str, str]) -> dict:
    """A property list dictionary from `key path: value` (paths separated by `/`)."""
    root: dict = {}
    for path, value in values.items():
        node = root
        *parents, leaf = path.split("/")
        for parent in parents:
            node = node.setdefault(parent, {})
        node[leaf] = value
    return root


def build_ipa(work: Path) -> bytes:
    plists: dict[str, dict[str, str]] = {}
    for _, placement, key, value in IOS_UNITS:
        if placement == "plist":
            file, path = key.split(":", 1)
            plists.setdefault(file, {})[path] = value
    source = work / "libsecrets.c"
    strings = [value for _, placement, _, value in IOS_UNITS if placement == "macho"]
    source.write_text(
        "const char *const fixture_strings[] = {\n"
        + "".join(f'    "{value}",\n' for value in strings)
        + "};\nconst char *fixture_string(int index) { return fixture_strings[index]; }\n"
    )
    sdk = subprocess.run(
        ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], check=True, capture_output=True, text=True
    ).stdout.strip()
    library = work / "libsecrets.dylib"
    run(
        "xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios17.0", "-isysroot", sdk, "-Os",
        "-dynamiclib", "-install_name", "@rpath/libsecrets.dylib", "-o", library, source,
    )
    run("codesign", "--force", "--sign", "-", library)
    entries: dict[str, bytes] = {}
    with zipfile.ZipFile(HERE.parent / "ios/ipa/fixture.ipa") as base:
        for info in base.infolist():
            if not info.is_dir():
                entries[info.filename] = base.read(info)
    entries[BUNDLE + "GoogleService-Info.plist"] = plistlib.dumps(plists["GoogleService-Info.plist"], fmt=plistlib.FMT_XML)
    entries[BUNDLE + "Config.plist"] = plistlib.dumps(plist_with(plists["Config.plist"]), fmt=plistlib.FMT_BINARY)
    entries[IOS_LIBRARY] = library.read_bytes()
    for path, text in IOS_FILES:
        entries[path] = text.encode()
    output = work / "secrets.ipa"
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, entries[name])
    return output.read_bytes()


def mobsf_functions(source: Path):
    """MobSF's own detection code, loaded from its files without its Django dependencies."""
    common = source / "mobsf/StaticAnalyzer/views/common"
    entropy: dict = {}
    exec(compile((common / "entropy.py").read_text(), "entropy.py", "exec"), entropy)
    detection: dict = {"get_entropies": entropy["get_entropies"]}
    text = (common / "secret_detection.py").read_text()
    text = text.replace(
        "from mobsf.StaticAnalyzer.views.common.entropy import (\n    get_entropies,\n)\n", ""
    )
    exec(compile(text, "secret_detection.py", "exec"), detection)
    shared = ast.parse((common / "shared_func.py").read_text())
    function = next(node for node in shared.body if isinstance(node, ast.FunctionDef) and node.name == "is_secret_key")
    secret_key: dict = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "shared_func.py", "exec"), secret_key)
    return detection["detect_known_secrets"], secret_key["is_secret_key"], entropy["get_entropies"]


def mobsf_code_string(text: str) -> bool:
    """MobSF `strings_and_entropies`' filter on code strings."""
    if len(text) < 4 or any(word in text for word in ("\\u0", "com.google.")):
        return False
    if any(word in text and "/" in text for word in ("Ljava", "Lkotlin", "kotlin", "android")):
        return False
    return text[0].isalnum()


def mobsf_verdicts(source: Path) -> list[str]:
    detect_known, is_secret_key, get_entropies = mobsf_functions(source)
    lines = []
    for name, placement, key, value in UNITS + IOS_UNITS:
        if placement in ("code", "static") and not mobsf_code_string(value):
            lines.append(f"{name}\tfiltered")
            continue
        known = sorted({found.split(": ", 1)[0] for found in detect_known(value)})
        key_name = "-"
        if placement in ("resource", "plist"):
            leaf = key.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
            key_name = "yes" if is_secret_key(leaf) and " " not in value else "no"
        runs = "-"
        if placement in ("code", "static", "native", "macho"):
            runs = ",".join(sorted(mask(run) for run in get_entropies((value,))))
        lines.append(f"{name}\tknown={'|'.join(known)}\tkey_name={key_name}\tentropy={runs}")
    for path, text in FILES + IOS_FILES:
        known = sorted({found.split(": ", 1)[0] for found in detect_known(text)})
        lines.append(f"{path}\tknown={'|'.join(known)}\tkey_name=-\tentropy=-")
    return lines


def gitleaks_verdicts(work: Path) -> list[str]:
    root = work / "gitleaks"
    for name, _, _, value in UNITS + IOS_UNITS:
        target = root / "units" / f"{name}.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)
    for path, text in FILES + IOS_FILES:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    (root / KEY_STORE).parent.mkdir(parents=True, exist_ok=True)
    (root / KEY_STORE).write_bytes(b"\0" * 16)
    report = work / "gitleaks.json"
    run(
        "gitleaks", "dir", root, "--no-banner", "--max-decode-depth", "0", "--report-format", "json",
        "--report-path", report, "--exit-code", "0", "--log-level", "error",
    )
    found: dict[str, list[str]] = {}
    for finding in json.loads(report.read_text()):
        relative = str(Path(finding["File"]).resolve().relative_to(root.resolve()))
        found.setdefault(relative, []).append(finding["RuleID"])
    lines = []
    for name, _, _, _ in UNITS + IOS_UNITS:
        lines.append(f"{name}\t{','.join(sorted(found.get(f'units/{name}.txt', [])))}")
    for path, _ in FILES + IOS_FILES + [(KEY_STORE, "")]:
        lines.append(f"{path}\t{','.join(sorted(found.get(path, [])))}")
    return lines


def main() -> None:
    mobsf = Path(os.environ["MOBSF_SRC"])
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (HERE / "secrets.apk").write_bytes(build_apk(work))
        (HERE / "secrets.ipa").write_bytes(build_ipa(work))
        (HERE / "units.txt").write_text(
            "".join(
                f"{name}\t{placement}\t{key or '-'}\t{mask(value)}\n"
                for name, placement, key, value in UNITS + IOS_UNITS
            )
            + "".join(f"{path}\tfile\t{path}\t{mask(text)}\n" for path, text in FILES + IOS_FILES)
        )
        (HERE / "mobsf-verdicts.txt").write_text("\n".join(mobsf_verdicts(mobsf)) + "\n")
        (HERE / "gitleaks-verdicts.txt").write_text("\n".join(gitleaks_verdicts(work)) + "\n")
    print(f"wrote {HERE}/secrets.apk, secrets.ipa, units.txt, mobsf-verdicts.txt, gitleaks-verdicts.txt")


if __name__ == "__main__":
    if shutil.which("gitleaks") is None:
        raise SystemExit("gitleaks 8.30.1 is needed on PATH")
    main()
