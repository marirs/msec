"""Assembles msec's IPA fixtures (run by build_ipa.sh, which compiles and signs the binaries).

    python3 -I make_ipa.py info <platform> <out-dir>
        Writes the Info.plist sources (XML) of the app, its framework and its extension for
        `iphoneos` or `iphonesimulator` into <out-dir>/{app,Lib,Share}.plist.
    python3 -I make_ipa.py variants <bundle> <out-dir>
        Copies the bundle (Fixture.app) once per variant below into
        <out-dir>/<variant>/Fixture.app, each changed in one way (build_ipa.sh signs them).
    python3 -I make_ipa.py tamper <out-dir>
        Changes the TAMPER variants after signing.
    python3 -I make_ipa.py ipa <out.ipa> <layout> <bundle>...
        Zips bundles into an IPA, deterministically (sorted, fixed timestamps, Unix modes kept).

The variants are installed into a simulator by build_ipa.sh, so iOS's installer says which
it accepts; the layouts probe where msec looks for the app bundle.
"""

import plistlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def app_info(platform):
    simulator = platform == "iphonesimulator"
    return {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": "Fixture",
        "CFBundleExecutable": "Fixture",
        "CFBundleIdentifier": "dev.appchk.fixture",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "Fixture",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "2.1",
        "CFBundleSupportedPlatforms": ["iPhoneSimulator" if simulator else "iPhoneOS"],
        "CFBundleURLTypes": [{"CFBundleURLName": "dev.appchk.fixture",
                              "CFBundleURLSchemes": ["fixture"]}],
        "CFBundleVersion": "42",
        "DTPlatformName": platform,
        "DTSDKName": f"{platform}27.1",
        "DTXcode": "2710",
        "ITSAppUsesNonExemptEncryption": False,
        "LSApplicationQueriesSchemes": ["whatsapp"],
        "LSRequiresIPhoneOS": True,
        "MinimumOSVersion": "17.0",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {"example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0",
                                                   "NSIncludesSubdomains": True}},
        },
        "NSCameraUsageDescription": "Scans documents.",
        "NSLocationWhenInUseUsageDescription": "Finds stores nearby.",
        "UIBackgroundModes": ["location"],
        "UIDeviceFamily": [1, 2],
        "UIFileSharingEnabled": True,
        "UIRequiredDeviceCapabilities": ["arm64"],
    }


def framework_info(platform):
    return {
        "CFBundleExecutable": "Lib",
        "CFBundleIdentifier": "dev.appchk.fixture.Lib",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "Lib",
        "CFBundlePackageType": "FMWK",
        "CFBundleShortVersionString": "1.0",
        "CFBundleSupportedPlatforms": [
            "iPhoneSimulator" if platform == "iphonesimulator" else "iPhoneOS"],
        "CFBundleVersion": "1",
        "MinimumOSVersion": "17.0",
    }


def extension_info(platform):
    return {
        "CFBundleDisplayName": "Share",
        "CFBundleExecutable": "Share",
        "CFBundleIdentifier": "dev.appchk.fixture.Share",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "Share",
        "CFBundlePackageType": "XPC!",
        "CFBundleShortVersionString": "2.1",
        "CFBundleSupportedPlatforms": [
            "iPhoneSimulator" if platform == "iphonesimulator" else "iPhoneOS"],
        "CFBundleVersion": "42",
        "MinimumOSVersion": "17.0",
        "NSExtension": {
            "NSExtensionAttributes": {"NSExtensionActivationRule": "TRUEPREDICATE"},
            "NSExtensionPointIdentifier": "com.apple.share-services",
            "NSExtensionPrincipalClass": "ShareViewController",
        },
    }


def write_info(platform, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, info in (("app", app_info(platform)), ("Lib", framework_info(platform)),
                       ("Share", extension_info(platform))):
        (out / f"{name}.plist").write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_XML))


def to_binary(path):
    subprocess.run(["plutil", "-convert", "binary1", str(path)], check=True)


def xml_info(bundle, text):
    (bundle / "Info.plist").write_text(text)


def info_with(bundle, changes):
    """Rewrites the bundle's Info.plist with keys changed (None deletes), in binary."""
    path = bundle / "Info.plist"
    info = plistlib.loads(path.read_bytes())
    for key, value in changes.items():
        if value is None:
            info.pop(key, None)
        else:
            info[key] = value
    path.write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))


def duplicate_identifier_xml(bundle):
    """Info.plist in XML with CFBundleIdentifier twice: Core Foundation keeps the last."""
    info = plistlib.loads((bundle / "Info.plist").read_bytes())
    info.pop("CFBundleIdentifier")
    text = plistlib.dumps(info, fmt=plistlib.FMT_XML).decode()
    duplicate = ("\t<key>CFBundleIdentifier</key>\n\t<string>dev.appchk.first</string>\n"
                 "\t<key>CFBundleIdentifier</key>\n\t<string>dev.appchk.fixture</string>\n")
    xml_info(bundle, text.replace("<dict>\n", "<dict>\n" + duplicate, 1))


def duplicate_identifier_binary(bundle):
    """CFBundleIdentifier twice in a binary plist, dev.appchk.first first: Core Foundation
    keeps the first. No plist writer emits duplicates, so plistlib's output is rewritten."""
    info = plistlib.loads((bundle / "Info.plist").read_bytes())
    info.pop("CFBundleIdentifier")
    data = plistlib.dumps({"CFBundleIdentifier": "dev.appchk.fixture", **info},
                          fmt=plistlib.FMT_BINARY, sort_keys=False)
    (bundle / "Info.plist").write_bytes(add_leading_duplicate(data, "CFBundleIdentifier",
                                                              "dev.appchk.first"))


def add_leading_duplicate(data, key, first_value):
    """Rewrites a binary plist whose top object is a dictionary so that `key` appears twice,
    `first_value` first. Objects are appended, references widened to 2 bytes."""
    import struct
    trailer = data[-32:]
    offset_size, ref_size = trailer[6], trailer[7]
    count, top, table = struct.unpack(">QQQ", trailer[8:])
    offsets = [int.from_bytes(data[table + i * offset_size: table + (i + 1) * offset_size], "big")
               for i in range(count)]

    def object_bytes(index):
        start = offsets[index]
        later = sorted(offset for offset in offsets if offset > start)
        end = later[0] if later else table
        return data[start:end]

    def refs(blob, at, n):
        return [int.from_bytes(blob[at + i * ref_size: at + (i + 1) * ref_size], "big")
                for i in range(n)]

    top_blob = object_bytes(top)
    marker = top_blob[0]
    assert marker & 0xF0 == 0xD0
    n, at = marker & 0x0F, 1
    if n == 0x0F:
        width = 1 << (top_blob[1] & 0x0F)
        n, at = int.from_bytes(top_blob[2:2 + width], "big"), 2 + width
    keys, values = refs(top_blob, at, n), refs(top_blob, at + n * ref_size, n)
    objects = [object_bytes(i) for i in range(count)]
    def ascii_object(text):
        raw = text.encode("ascii")
        header = bytes([0x50 | len(raw)]) if len(raw) < 15 else bytes([0x5F, 0x10, len(raw)])
        return header + raw

    key_object, value_object = ascii_object(key), ascii_object(first_value)
    objects += [key_object, value_object]
    keys, values = [count] + keys, [count + 1] + values

    def encode_refs(indices):
        return b"".join(index.to_bytes(2, "big") for index in indices)

    n = len(keys)
    header = bytes([0xD0 | n]) if n < 15 else bytes([0xDF, 0x10, n])
    rewritten = []
    for index, blob in enumerate(objects):
        if index == top:
            rewritten.append(header + encode_refs(keys) + encode_refs(values))
            continue
        kind = blob[0] & 0xF0
        if kind in (0xA0, 0xD0):
            m, at = blob[0] & 0x0F, 1
            prefix = blob[:1]
            if m == 0x0F:
                width = 1 << (blob[1] & 0x0F)
                m, at = int.from_bytes(blob[2:2 + width], "big"), 2 + width
                prefix = blob[:at]
            total = m * (2 if kind == 0xD0 else 1)
            rewritten.append(prefix + encode_refs(refs(blob, at, total)))
        else:
            rewritten.append(blob)
    body = b"bplist00"
    new_offsets = []
    for blob in rewritten:
        new_offsets.append(len(body))
        body += blob
    table = len(body)
    size = max(1, (max(new_offsets).bit_length() + 7) // 8)
    for offset in new_offsets:
        body += offset.to_bytes(size, "big")
    return body + b"\0" * 6 + struct.pack(">BBQQQ", size, 2, len(rewritten), top, table)


VARIANTS = {
    # The bundle as built.
    "fixture": lambda bundle: None,
    "no-info-plist": lambda bundle: (bundle / "Info.plist").unlink(),
    "info-plist-truncated": lambda bundle: (bundle / "Info.plist").write_bytes(
        (bundle / "Info.plist").read_bytes()[:100]),
    "info-plist-array": lambda bundle: (bundle / "Info.plist").write_bytes(
        plistlib.dumps(["not", "a", "dictionary"], fmt=plistlib.FMT_BINARY)),
    "executable-not-declared": lambda bundle: info_with(bundle, {"CFBundleExecutable": None}),
    "executable-missing": lambda bundle: info_with(bundle, {"CFBundleExecutable": "Missing"}),
    "executable-traversal": lambda bundle: info_with(bundle,
                                                     {"CFBundleExecutable": "../Fixture"}),
    "identifier-integer": lambda bundle: info_with(bundle, {"CFBundleIdentifier": 42}),
    "duplicate-identifier-xml": duplicate_identifier_xml,
    "duplicate-identifier-binary": duplicate_identifier_binary,
    # Changed after signing (see TAMPER): signed as built.
    "info-plist-after-signing": lambda bundle: None,
    "executable-after-signing": lambda bundle: None,
}


def bump_version(bundle):
    info = plistlib.loads((bundle / "Info.plist").read_bytes())
    info["CFBundleShortVersionString"] = "9.9"
    (bundle / "Info.plist").write_bytes(plistlib.dumps(info, fmt=plistlib.FMT_BINARY))


def flip_code_byte(bundle):
    """Changes one byte of the main executable's first code page, past the load commands."""
    executable = bundle / "Fixture"
    data = bytearray(executable.read_bytes())
    data[16384 + 16] ^= 0xFF
    executable.write_bytes(bytes(data))


# Changes made after signing, so the signature no longer matches.
TAMPER = {
    "info-plist-after-signing": bump_version,
    "executable-after-signing": flip_code_byte,
}


def variants(bundle, out):
    bundle, out = Path(bundle), Path(out)
    for name, change in VARIANTS.items():
        target = out / name / "Fixture.app"
        shutil.copytree(bundle, target, symlinks=True)
        change(target)


def tamper(out):
    for name, change in TAMPER.items():
        change(Path(out) / name / "Fixture.app")


def entries(bundle, prefix):
    """(archive name, path) for a bundle directory and everything in it, sorted."""
    bundle = Path(bundle)
    yield prefix + "/", bundle
    for path in sorted(bundle.rglob("*")):
        name = prefix + "/" + path.relative_to(bundle).as_posix()
        yield (name + "/" if path.is_dir() else name), path


def write_ipa(out, layout, bundles):
    """Layouts: payload (Payload/Fixture.app), two-apps (a second copy as Payload/Other.app),
    not-in-payload (Fixture.app at the root), no-app (the bundle's files, no .app directory),
    empty (no entries)."""
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        if layout == "empty":
            return
        prefixes = {
            "payload": ["Payload/Fixture.app"],
            "two-apps": ["Payload/Fixture.app", "Payload/Other.app"],
            "not-in-payload": ["Fixture.app"],
            "no-app": ["Payload/Fixture"],
        }[layout]
        listing = []
        for prefix in prefixes:
            listing.extend(entries(bundles[0], prefix))
        if layout == "payload":
            listing.insert(0, ("Payload/", None))
        for name, path in sorted(listing, key=lambda item: item[0]):
            info = zipfile.ZipInfo(name, date_time=TIMESTAMP)
            info.create_system = 3
            if path is None or path.is_dir():
                info.external_attr = (0o40755 << 16) | 0x10
                archive.writestr(info, b"")
                continue
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())


def main():
    command = sys.argv[1]
    if command == "info":
        write_info(sys.argv[2], sys.argv[3])
    elif command == "variants":
        variants(sys.argv[2], sys.argv[3])
    elif command == "tamper":
        tamper(sys.argv[2])
    elif command == "ipa":
        write_ipa(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        raise SystemExit(f"unknown command {command}")


if __name__ == "__main__":
    main()
