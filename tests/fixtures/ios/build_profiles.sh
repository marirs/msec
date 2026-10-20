#!/bin/sh
# Rebuilds msec's provisioning-profile fixtures (profiles/) and the oracles' reading of them:
# - profiles/<name>.mobileprovision: make_profiles.py's plists, signed as CMS SignedData with
#   attached content by a fresh test certificate chain (a root, and a signing certificate it
#   issues; nothing here is Apple's), as DER; development-ber.mobileprovision is the
#   development profile streamed (BER, indefinite lengths), tampered.mobileprovision has one
#   content byte changed after signing, and not-signed.mobileprovision is a bare plist;
# - profiles/<name>.content.plist: what Apple's `security cms -D` decodes from each;
# - profiles/verdicts.txt: whether `openssl cms -verify -noverify` accepts each signature (the
#   signature alone: the test chain is not trusted by anything).
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
"$openssl" req -newkey rsa:2048 -nodes -subj "/CN=msec Test Provisioning Profile Signing" \
  -keyout "$work/signer.key" -out "$work/signer.csr" 2> /dev/null
"$openssl" x509 -req -in "$work/signer.csr" -CA "$work/root.pem" -CAkey "$work/root.key" \
  -CAcreateserial -days 3650 -out "$work/signer.pem" 2> /dev/null
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=msec Development Certificate" \
  -keyout "$work/developer.key" -outform DER -out "$work/developer.der" 2> /dev/null

rm -rf profiles
mkdir profiles
python3 -I make_profiles.py "$work/developer.der" "$work/plists"
sign() { # plist, output, extra flags...
  input="$1" output="$2"
  shift 2
  "$openssl" cms -sign -nodetach -binary -outform DER -in "$input" -signer "$work/signer.pem" \
    -inkey "$work/signer.key" -certfile "$work/root.pem" -md sha256 "$@" -out "$output"
}
for plist in "$work"/plists/*.plist; do
  sign "$plist" "profiles/$(basename "$plist" .plist).mobileprovision"
done
sign "$work/plists/development.plist" profiles/development-ber.mobileprovision -stream
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
