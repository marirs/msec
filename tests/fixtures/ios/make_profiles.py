"""Writes the plist content of msec's provisioning-profile fixtures (build_profiles.sh signs
them with a test CA; nothing here is Apple's).

    python3 -I make_profiles.py <developer-certificate.der> <out-dir>

One <name>.plist per profile kind and per mismatch the tests need. Dates are fixed so the
tests can name them: created 2026-01-01, expiring 2036-01-01 (expired.plist: 2026-01-31).
"""

import datetime
import plistlib
import sys
from pathlib import Path

TEAM = "A1B2C3D4E5"
DEVICES = ["00008110-000A1B2C3D4E5F01", "00008110-000A1B2C3D4E5F02"]
CREATED = datetime.datetime(2026, 1, 1)
EXPIRES = datetime.datetime(2036, 1, 1)


def profile(certificate, name, application, devices=None, all_devices=False, debuggable=False,
            keychain=True, expires=EXPIRES):
    entitlements = {
        "application-identifier": f"{TEAM}.{application}",
        "com.apple.developer.team-identifier": TEAM,
        "get-task-allow": debuggable,
    }
    if keychain:
        entitlements["keychain-access-groups"] = [f"{TEAM}.*"]
    content = {
        "AppIDName": "Fixture",
        "ApplicationIdentifierPrefix": [TEAM],
        "CreationDate": CREATED,
        "DeveloperCertificates": [certificate],
        "Entitlements": entitlements,
        "ExpirationDate": expires,
        "IsXcodeManaged": False,
        "Name": name,
        "Platform": ["iOS"],
        "TeamIdentifier": [TEAM],
        "TeamName": "msec Fixture Team",
        "TimeToLive": (expires - CREATED).days,
        "UUID": "00000000-0000-4000-8000-" + name.encode().hex()[:12].ljust(12, "0"),
        "Version": 1,
    }
    if devices is not None:
        content["ProvisionedDevices"] = devices
    if all_devices:
        content["ProvisionsAllDevices"] = True
    return plistlib.dumps(content, fmt=plistlib.FMT_XML)


def main():
    certificate = Path(sys.argv[1]).read_bytes()
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    fixture = "dev.appchk.fixture"
    profiles = {
        "development": profile(certificate, "Fixture Development", fixture, DEVICES,
                               debuggable=True),
        "ad-hoc": profile(certificate, "Fixture Ad Hoc", fixture, DEVICES),
        "enterprise": profile(certificate, "Fixture In House", fixture, all_devices=True),
        "app-store": profile(certificate, "Fixture App Store", fixture),
        "wildcard": profile(certificate, "Fixture Wildcard", "*", DEVICES, debuggable=True),
        "expired": profile(certificate, "Fixture Expired", fixture, DEVICES, debuggable=True,
                           expires=datetime.datetime(2026, 1, 31)),
        "other-bundle": profile(certificate, "Fixture Other", "dev.appchk.other", DEVICES,
                                debuggable=True),
        "no-keychain": profile(certificate, "Fixture No Keychain", fixture, DEVICES,
                               debuggable=True, keychain=False),
    }
    for name, content in profiles.items():
        (out / f"{name}.plist").write_bytes(content)


if __name__ == "__main__":
    main()
