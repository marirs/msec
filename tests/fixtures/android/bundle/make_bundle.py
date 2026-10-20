#!/usr/bin/env python3
"""Assembles msec's app bundle fixtures from aapt2's protobuf output (no third-party input).

    python3 -I make_bundle.py <work-dir> <dex> <native-library> <out-dir>

<work-dir> holds base.zip, camera.zip and textures.zip from `aapt2 link --proto-format`. The
layout follows bundletool's app bundle format: each module's manifest under
<module>/manifest/, its resource table and res/ at the module root, DEX files under dex/,
native libraries under lib/<abi>/, assets under assets/, and BundleConfig.pb at the root.
bundletool itself is not used, so BundleConfig.pb names no real bundletool version.
"""

import sys
import zipfile
from pathlib import Path

FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def bundle_config():
    # BundleConfig { bundletool { version: "0.0.0-fixture" } }: field 1 holding field 2.
    version = b"0.0.0-fixture"
    bundletool = bytes([0x12, len(version)]) + version
    return bytes([0x0A, len(bundletool)]) + bundletool


def module_files(module, linked, resources=True):
    """(path in the bundle, bytes) for an aapt2 --proto-format output zip. Asset packs keep no
    resource table (bundletool refuses one)."""
    with zipfile.ZipFile(linked) as archive:
        for name in sorted(archive.namelist()):
            data = archive.read(name)
            if name == "resources.pb" and not resources:
                continue
            if name == "AndroidManifest.xml":
                yield f"{module}/manifest/AndroidManifest.xml", data
            else:
                yield f"{module}/{name}", data


def write(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files:
            info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def main():
    work, dex, library, out = (Path(argument) for argument in sys.argv[1:])
    base = [("BundleConfig.pb", bundle_config())]
    base += list(module_files("base", work / "base.zip"))
    base += [
        ("base/dex/classes.dex", dex.read_bytes()),
        ("base/lib/arm64-v8a/libapp.so", library.read_bytes()),
    ]
    write(out / "bundle-base.aab", base)
    features = list(module_files("camera", work / "camera.zip"))
    textures = list(module_files("textures", work / "textures.zip", resources=False))
    textures.append(("textures/assets/textures/stone.txt", (Path(__file__).parent / "textures/assets/textures/stone.txt").read_bytes()))
    write(out / "bundle.aab", base + features + textures)


if __name__ == "__main__":
    main()
