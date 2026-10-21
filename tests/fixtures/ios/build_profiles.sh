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
#   self-signed.mobileprovision by a self-signed certificate that has it. Three more are
#   built against Apple's own public CA certificates (apple/, below), as forgeries would be:
#   forged-apple-link.mobileprovision is signed by a certificate named like Apple's profile
#   signer and naming Apple's intermediate as its issuer, but issued by another key, and
#   carries Apple's genuine intermediate and root (the chain is anchored at Apple, its first
#   link fails); incomplete-apple-chain.mobileprovision is signed by the same certificate and
#   carries nothing else (its issuer is missing); apple-named-root.mobileprovision is signed
#   under a self-signed root named "Apple Root CA - G9" that Apple never issued;
# - profiles/root.der: the test root, for tests to trust;
# - profiles/<name>.content.plist: what Apple's `security cms -D` decodes from each;
# - profiles/verdicts.txt: whether `openssl cms -verify -noverify` accepts each signature (the
#   signature alone: the test chain is not trusted by anything);
# - profiles/trust-verdicts.txt: whether `openssl cms -verify -CAfile root.pem` accepts each
#   (the signer's chain to the test root), whether the signer carries the extension, and what
#   `openssl cms -verify -CAfile apple/apple-root-ca.der` says of the chain to Apple's root.
# apple/ holds Apple Root CA and Apple iPhone Certification Authority (DER), public CA
# certificates taken from an Apple-issued provisioning profile (Apple also publishes them at
# https://www.apple.com/certificateauthority/); no private key of Apple's is involved.
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

# Forgeries against Apple's own CA certificates (see above).
"$openssl" x509 -inform DER -in apple/apple-root-ca.der -out "$work/apple-root.pem"
"$openssl" x509 -inform DER -in apple/apple-iphone-certification-authority.der \
  -out "$work/apple-ca.pem"
cat "$work/apple-ca.pem" "$work/apple-root.pem" > "$work/apple-chain.pem"
# The forged CA copies the genuine intermediate's name and key identifier, so the forged signer
# names Apple's intermediate as its issuer in both ways a verifier matches issuers by.
apple_key_id=$("$openssl" x509 -in "$work/apple-ca.pem" -noout -ext subjectKeyIdentifier |
  sed -n '2p' | tr -d ' ')
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/CN=Apple iPhone Certification Authority/OU=Certification Authority/O=Apple Inc./C=US" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=$apple_key_id" \
  -keyout "$work/forged-ca.key" -out "$work/forged-ca.pem" 2> /dev/null
"$openssl" req -newkey rsa:2048 -nodes \
  -subj "/CN=Apple iPhone OS Provisioning Profile Signing/O=Apple Inc./C=US" \
  -keyout "$work/forged-apple.key" -out "$work/forged-apple.csr" 2> /dev/null
"$openssl" x509 -req -in "$work/forged-apple.csr" -CA "$work/forged-ca.pem" \
  -CAkey "$work/forged-ca.key" -CAcreateserial -days 3650 -extfile "$work/profile-signer.ext" \
  -out "$work/forged-apple.pem" 2> /dev/null
"$openssl" req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/CN=Apple Root CA - G9/OU=Apple Certification Authority/O=Apple Inc./C=US" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$work/apple-named-root.key" -out "$work/apple-named-root.pem" 2> /dev/null
"$openssl" req -newkey rsa:2048 -nodes \
  -subj "/CN=Apple iPhone OS Provisioning Profile Signing/O=Apple Inc./C=US" \
  -keyout "$work/apple-named-signer.key" -out "$work/apple-named-signer.csr" 2> /dev/null
"$openssl" x509 -req -in "$work/apple-named-signer.csr" -CA "$work/apple-named-root.pem" \
  -CAkey "$work/apple-named-root.key" -CAcreateserial -days 3650 \
  -extfile "$work/profile-signer.ext" -out "$work/apple-named-signer.pem" 2> /dev/null

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
  sign_carrying "$work/root.pem" "$signer" "$input" "$output" "$@"
}
sign_carrying() { # certificates carried besides the signer's ("none"), signer, plist, output
  carried="$1" signer="$2" input="$3" output="$4"
  shift 4
  if [ "$carried" = none ]; then
    set -- "$@"
  else
    set -- -certfile "$carried" "$@"
  fi
  "$openssl" cms -sign -nodetach -binary -outform DER -in "$input" \
    -signer "$work/$signer.pem" -inkey "$work/$signer.key" -md sha256 "$@" -out "$output"
}
for plist in "$work"/plists/*.plist; do
  sign "$plist" "profiles/$(basename "$plist" .plist).mobileprovision"
done
sign "$work/plists/development.plist" profiles/development-ber.mobileprovision -stream
sign_as developer-signer "$work/plists/development.plist" \
  profiles/developer-signed.mobileprovision
sign_as self-signer "$work/plists/development.plist" profiles/self-signed.mobileprovision
sign_carrying "$work/apple-chain.pem" forged-apple "$work/plists/development.plist" \
  profiles/forged-apple-link.mobileprovision
sign_carrying none forged-apple "$work/plists/development.plist" \
  profiles/incomplete-apple-chain.mobileprovision
sign_carrying "$work/apple-named-root.pem" apple-named-signer "$work/plists/development.plist" \
  profiles/apple-named-root.mobileprovision
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
  apple=$("$openssl" cms -verify -binary -inform DER -in "$profile" \
    -CAfile "$work/apple-root.pem" -purpose any -out /dev/null 2>&1 |
    grep -o "Verify error: .*" | head -n 1 | sed 's/Verify error: //')
  if [ -z "$apple" ] && "$openssl" cms -verify -binary -inform DER -in "$profile" \
    -CAfile "$work/apple-root.pem" -purpose any -out /dev/null > /dev/null 2>&1; then
    apple="verifies"
  fi
  echo "$name: $chain; $extension; to Apple's root: ${apple:-signature does not verify}"
done > profiles/trust-verdicts.txt
