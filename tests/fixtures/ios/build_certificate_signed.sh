#!/bin/sh
# Rebuilds msec's certificate-signed IPA fixtures and codesign's reading of them. Run after
# build_ipa.sh: each variant is ipa/fixture.ipa's bundle with a provisioning profile that lists a
# test signing certificate, sealed again by codesign (ad hoc), then its main executable
# re-signed with that certificate by resign.py (codesign signs only with identities in the
# user's keychain search list, which a fixture build must not touch). The certificate chain is
# a test root, an intermediate named like Apple's WWDR, and "Apple Development" / "Apple
# Distribution" certificates for team A1B2C3D4E5; nothing here is Apple's.
# - ipa/certificate-development.ipa: development certificate, development profile;
# - ipa/certificate-distribution.ipa: distribution certificate, App Store profile, entitlements
#   without get-task-allow;
# - ipa/certificate-not-in-profile.ipa: distribution certificate, an App Store profile that
#   lists only the development certificate;
# - ipa/certificate-development-app-store.ipa: development certificate, an App Store profile
#   that lists it (so only the certificate's use does not fit the distribution method);
# - ipa/certificate-cms-tampered.ipa: as distribution, one byte of the CMS signature changed;
# - ipa/certificate-ed25519.ipa: as distribution, signed by an Ed25519 "Apple Distribution"
#   certificate, an algorithm msec does not verify in code signatures;
# - ipa/certificate-team-mismatch.ipa: as distribution, the CodeDirectory names another team;
# - certificate-verdicts.txt: per variant, the authorities and team codesign -dvvv reads, and
#   codesign --verify's verdict on the bundle;
# - certificates/: the test chain's certificates (DER), for the tests to compare with.
# Needs macOS (codesign, plutil), OpenSSL 3 (OPENSSL, else Homebrew's openssl@3) and python3.
set -eu
cd "$(dirname "$0")"
openssl="${OPENSSL:-}"
if [ -z "$openssl" ]; then
  if [ -x /opt/homebrew/opt/openssl@3/bin/openssl ]; then
    openssl=/opt/homebrew/opt/openssl@3/bin/openssl
  else
    openssl=openssl
  fi
fi
export OPENSSL="$openssl"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

ca_ext="$work/ca.ext"
leaf_ext="$work/leaf.ext"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$ca_ext"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,codeSigning\n' > "$leaf_ext"
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=msec Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$work/root.key" -out "$work/root.pem" 2> /dev/null
issue() { # name, subject, issuer, extensions[, key type]
  "$openssl" req -newkey "${5:-rsa:2048}" -nodes -subj "$2" -keyout "$work/$1.key" \
    -out "$work/$1.csr" 2> /dev/null
  "$openssl" x509 -req -in "$work/$1.csr" -CA "$work/$3.pem" -CAkey "$work/$3.key" \
    -CAcreateserial -days 3650 -extfile "$4" -out "$work/$1.pem" 2> /dev/null
  "$openssl" x509 -in "$work/$1.pem" -outform DER -out "$work/$1.der"
}
issue wwdr "/CN=msec Test Worldwide Developer Relations/OU=G3/O=msec Test/C=US" root "$ca_ext"
issue development "/CN=Apple Development: msec Fixture (P1Q2R3S4T5)/OU=A1B2C3D4E5/O=msec Fixture/C=US" wwdr "$leaf_ext"
issue distribution "/CN=Apple Distribution: msec Fixture (A1B2C3D4E5)/OU=A1B2C3D4E5/O=msec Fixture/C=US" wwdr "$leaf_ext"
issue ed25519 "/CN=Apple Distribution: msec Fixture (A1B2C3D4E5)/OU=A1B2C3D4E5/O=msec Fixture/C=US" wwdr "$leaf_ext" ed25519
issue profiles "/CN=msec Test Provisioning Profile Signing" root "$leaf_ext"
cat "$work/wwdr.pem" "$work/root.pem" > "$work/chain.pem"
rm -rf certificates
mkdir certificates
"$openssl" x509 -in "$work/root.pem" -outform DER -out certificates/root.der
cp "$work/wwdr.der" "$work/development.der" "$work/distribution.der" certificates/

# A signed provisioning profile of make_profiles.py's kind `kind`, listing `certificate`.
profile() { # kind, certificate, output
  python3 -I - "$1" "$work/$2.der" "$work/$1-$2.plist" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, ".")
import make_profiles
kind, certificate, out = sys.argv[1], Path(sys.argv[2]).read_bytes(), sys.argv[3]
fixture = "dev.appchk.fixture"
content = {
    "development": lambda: make_profiles.profile(certificate, "Fixture Development", fixture,
                                                 make_profiles.DEVICES, debuggable=True),
    "app-store": lambda: make_profiles.profile(certificate, "Fixture App Store", fixture),
}[kind]()
Path(out).write_bytes(content)
PY
  "$openssl" cms -sign -nodetach -binary -outform DER -in "$work/$1-$2.plist" \
    -signer "$work/profiles.pem" -inkey "$work/profiles.key" -certfile "$work/root.pem" \
    -md sha256 -out "$3"
}

python3 -I - "$work/distribution.entitlements" <<'PY'
import plistlib
import sys
from pathlib import Path
entitlements = plistlib.loads(Path("app/entitlements.plist").read_bytes())
entitlements["get-task-allow"] = False
Path(sys.argv[1]).write_bytes(plistlib.dumps(entitlements))
PY

variant() { # name, certificate, profile kind, profile certificate, entitlements, team, resign flags...
  name="$1" certificate="$2" kind="$3" listed="$4" entitlements="$5" team="$6"
  shift 6
  bundle="$work/$name/Payload/Fixture.app"
  mkdir -p "$work/$name"
  (cd "$work/$name" && unzip -q "$OLDPWD/ipa/fixture.ipa")
  profile "$kind" "$listed" "$bundle/embedded.mobileprovision"
  codesign -s - -f --timestamp=none --entitlements "$entitlements" "$bundle" > /dev/null 2>&1
  python3 -I resign.py "$bundle/Fixture" "$work/$certificate.pem" "$work/$certificate.key" \
    "$work/chain.pem" "$team" "$@"
  python3 -I make_ipa.py ipa "ipa/certificate-$name.ipa" payload "$bundle"
  {
    echo "$name:"
    codesign -dvvv "$bundle" 2>&1 | grep -E '^(Authority|TeamIdentifier)=' | sed 's/^/  /'
    if codesign --verify --deep --strict "$bundle" > /dev/null 2> "$work/log"; then
      echo "  verify: valid"
    else
      echo "  verify: $(sed -e "s|$bundle|Fixture.app|g" "$work/log" | head -n 1 | cut -c 1-160)"
    fi
  } >> "$work/verdicts.txt"
}

rm -f ipa/certificate-*.ipa
variant development development development development app/entitlements.plist A1B2C3D4E5
variant distribution distribution app-store distribution "$work/distribution.entitlements" A1B2C3D4E5
variant not-in-profile distribution app-store development "$work/distribution.entitlements" A1B2C3D4E5
variant development-app-store development app-store development "$work/distribution.entitlements" A1B2C3D4E5
variant cms-tampered distribution app-store distribution "$work/distribution.entitlements" A1B2C3D4E5 --tamper-cms
variant team-mismatch distribution app-store distribution "$work/distribution.entitlements" Z9Y8X7W6V5
variant ed25519 ed25519 app-store ed25519 "$work/distribution.entitlements" A1B2C3D4E5 --sha512
cp "$work/verdicts.txt" certificate-verdicts.txt
