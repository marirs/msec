#!/bin/sh
# Rebuilds msec's provisioning-profile fixtures (profiles/) and the oracles' reading of them:
# - profiles/<name>.mobileprovision: make_profiles.py's plists, signed as CMS SignedData with
#   attached content by a fresh test certificate chain (a root, and a signing certificate it
#   issues; nothing here is Apple's), as DER; development-ber.mobileprovision is the
#   development profile streamed (BER, indefinite lengths), tampered.mobileprovision has one
#   content byte changed after signing, and not-signed.mobileprovision is a bare plist. The
#   signing certificate carries Apple's provisioning-profile signing extension
#   (1.2.840.113635.100.6.58), as Apple's does, so tests that trust the test root exercise the
#   whole trust check. Two profiles stand for forgeries of a development profile:
#   developer-signed.mobileprovision is signed by a certificate the test root issued without
#   that extension (as a developer's own Apple-issued certificate would be), and
#   self-signed.mobileprovision by a self-signed certificate that has it;
# - profiles/root.der: the test root, for tests to trust;
# - profiles/<name>.content.plist: what Apple's `security cms -D` decodes from each;
# - profiles/verdicts.txt: whether `openssl cms -verify -noverify` accepts each signature (the
#   signature alone: the test chain is not trusted by anything);
# - profiles/trust-verdicts.txt: whether `openssl cms -verify -CAfile root.pem` accepts each
#   (the signer's chain to the test root), and whether the signer carries the extension.
# Needs OpenSSL 3 (OPENSSL, else Homebrew's openssl@3, else openssl on PATH: LibreSSL has no
# cms command), macOS's security, and python3.
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
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$openssl" req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=msec Test Root CA" \
  -keyout "$work/root.key" -out "$work/root.pem" 2> /dev/null
# Apple's profile signer carries this extension, a DER NULL; a developer certificate does not.
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n1.2.840.113635.100.6.58=DER:0500\n' \
  > "$work/profile-signer.ext"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' \
  > "$work/plain-signer.ext"
"$openssl" req -newkey rsa:2048 -nodes -subj "/CN=msec Test Provisioning Profile Signing" \
  -keyout "$work/signer.key" -out "$work/signer.csr" 2> /dev/null
"$openssl" x509 -req -in "$work/signer.csr" -CA "$work/root.pem" -CAkey "$work/root.key" \
  -CAcreateserial -days 3650 -extfile "$work/profile-signer.ext" -out "$work/signer.pem" \
  2> /dev/null
"$openssl" req -newkey rsa:2048 -nodes -subj "/CN=msec Test Developer Certificate" \
  -keyout "$work/developer-signer.key" -out "$work/developer-signer.csr" 2> /dev/null
"$openssl" x509 -req -in "$work/developer-signer.csr" -CA "$work/root.pem" \
  -CAkey "$work/root.key" -CAcreateserial -days 3650 -extfile "$work/plain-signer.ext" \
  -out "$work/developer-signer.pem" 2> /dev/null
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/CN=msec Self-Signed Profile Signing" -addext "1.2.840.113635.100.6.58=DER:0500" \
  -keyout "$work/self-signer.key" -out "$work/self-signer.pem" 2> /dev/null
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=msec Development Certificate" \
  -keyout "$work/developer.key" -outform DER -out "$work/developer.der" 2> /dev/null

rm -rf profiles
mkdir profiles
"$openssl" x509 -in "$work/root.pem" -outform DER -out profiles/root.der
python3 -I make_profiles.py "$work/developer.der" "$work/plists"
sign() { # plist, output, extra flags...
  input="$1" output="$2"
  shift 2
  sign_as signer "$input" "$output" "$@"
}
sign_as() { # signer, plist, output, extra flags...
  signer="$1" input="$2" output="$3"
  shift 3
  "$openssl" cms -sign -nodetach -binary -outform DER -in "$input" \
    -signer "$work/$signer.pem" -inkey "$work/$signer.key" -certfile "$work/root.pem" \
    -md sha256 "$@" -out "$output"
}
for plist in "$work"/plists/*.plist; do
  sign "$plist" "profiles/$(basename "$plist" .plist).mobileprovision"
done
sign "$work/plists/development.plist" profiles/development-ber.mobileprovision -stream
sign_as developer-signer "$work/plists/development.plist" \
  profiles/developer-signed.mobileprovision
sign_as self-signer "$work/plists/development.plist" profiles/self-signed.mobileprovision
python3 -I - profiles/development.mobileprovision profiles/tampered.mobileprovision <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
at = data.index(b"Fixture Development")
data[at] = ord("f")  # one content byte: the plist still reads, the signature no longer does
open(sys.argv[2], "wb").write(data)
PY
cp "$work/plists/development.plist" profiles/not-signed.mobileprovision

for profile in profiles/*.mobileprovision; do
  name="$(basename "$profile" .mobileprovision)"
  security cms -D -i "$profile" > "profiles/$name.content.plist" 2> /dev/null ||
    rm -f "profiles/$name.content.plist"
  if "$openssl" cms -verify -noverify -binary -inform DER -in "$profile" -out /dev/null \
    > /dev/null 2>&1; then
    echo "$name: verified"
  else
    echo "$name: not verified"
  fi
done > profiles/verdicts.txt

for profile in profiles/*.mobileprovision; do
  name="$(basename "$profile" .mobileprovision)"
  if "$openssl" cms -verify -binary -inform DER -in "$profile" -CAfile "$work/root.pem" \
    -purpose any -out /dev/null > /dev/null 2>&1; then
    chain="chains to the test root"
  else
    chain="does not chain to the test root"
  fi
  "$openssl" cms -verify -noverify -inform DER -in "$profile" -signer "$work/found.pem" \
    -out /dev/null > /dev/null 2>&1 || : > "$work/found.pem"
  if [ -s "$work/found.pem" ] &&
    "$openssl" x509 -in "$work/found.pem" -noout -text | grep -q "1.2.840.113635.100.6.58"; then
    extension="profile-signing extension"
  else
    extension="no profile-signing extension"
  fi
  echo "$name: $chain; $extension"
done > profiles/trust-verdicts.txt
