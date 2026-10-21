#!/bin/sh
# Rebuilds msec's distribution-method fixtures (ipa/distribution-*.ipa) and the oracles' reading
# of them (distribution-verdicts.txt). Run after build_ipa.sh and build_profiles.sh: each
# variant is ipa/fixture.ipa's bundle (whose entitlements set get-task-allow) with its
# embedded.mobileprovision replaced, then sealed again by codesign (ad hoc, same entitlements):
# - distribution-development.ipa, distribution-ad-hoc.ipa, distribution-enterprise.ipa,
#   distribution-app-store.ipa: the profiles/ profile of that kind;
# - distribution-tampered-profile.ipa: profiles/tampered.mobileprovision (a development
#   profile with one content byte changed after signing);
# - distribution-developer-signed.ipa, distribution-self-signed.ipa: a development profile
#   signed by a certificate without the profile-signing extension, and by a self-signed one
#   (forgeries: their signatures verify);
# - distribution-no-profile.ipa: no profile at all.
# distribution-verdicts.txt, per variant: get-task-allow as codesign reads the entitlements;
# the profile's ProvisionsAllDevices, number of ProvisionedDevices and get-task-allow as
# `security cms -D` decodes them; whether `openssl cms -verify -noverify` accepts its signature;
# whether `openssl cms -verify -CAfile` accepts its signer's chain to the test root
# (profiles/root.der); and whether its signer carries Apple's profile-signing extension.
# Needs macOS (codesign, security, plutil), OpenSSL 3 (OPENSSL, else Homebrew's openssl@3) and
# python3.
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
"$openssl" x509 -inform DER -in profiles/root.der -out "$work/root.pem"

# A key of a plist on standard input, as plutil prints it (`missing` when absent).
plist_value() { # key
  plutil -extract "$1" raw -o - - 2> /dev/null || echo missing
}

variant() { # name, profile (or "none")
  name="$1" profile="$2"
  bundle="$work/$name/Payload/Fixture.app"
  mkdir -p "$work/$name"
  (cd "$work/$name" && unzip -q "$OLDPWD/ipa/fixture.ipa")
  rm -f "$bundle/embedded.mobileprovision"
  if [ "$profile" != none ]; then
    cp "profiles/$profile.mobileprovision" "$bundle/embedded.mobileprovision"
  fi
  codesign -s - -f --timestamp=none --entitlements app/entitlements.plist "$bundle" \
    > /dev/null 2>&1
  python3 -I make_ipa.py ipa "ipa/distribution-$name.ipa" payload "$bundle"
  {
    echo "$name:"
    allow=$(codesign -d --entitlements - --xml "$bundle" 2> /dev/null | plist_value get-task-allow)
    echo "  get-task-allow: $allow"
    if [ "$profile" = none ]; then
      echo "  profile: none"
    else
      security cms -D -i "$bundle/embedded.mobileprovision" > "$work/content.plist" 2> /dev/null
      echo "  profile: present"
      echo "  ProvisionsAllDevices: $(plist_value ProvisionsAllDevices < "$work/content.plist")"
      devices=$(plutil -extract ProvisionedDevices raw -o - "$work/content.plist" 2> /dev/null ||
        echo 0)
      echo "  ProvisionedDevices: $devices"
      echo "  profile get-task-allow: $(plutil -extract Entitlements.get-task-allow raw -o - \
        "$work/content.plist" 2> /dev/null || echo missing)"
      if "$openssl" cms -verify -noverify -inform DER -in "$bundle/embedded.mobileprovision" \
        -out /dev/null > /dev/null 2>&1; then
        echo "  signature: verifies"
      else
        echo "  signature: does not verify"
      fi
      if "$openssl" cms -verify -inform DER -in "$bundle/embedded.mobileprovision" \
        -CAfile "$work/root.pem" -purpose any -out /dev/null > /dev/null 2>&1; then
        echo "  chain: to the test root"
      else
        echo "  chain: not to the test root"
      fi
      : > "$work/signer.pem"
      "$openssl" cms -verify -noverify -inform DER -in "$bundle/embedded.mobileprovision" \
        -signer "$work/signer.pem" -out /dev/null > /dev/null 2>&1 || :
      if [ -s "$work/signer.pem" ] && "$openssl" x509 -in "$work/signer.pem" -noout -text |
        grep -q "1.2.840.113635.100.6.58"; then
        echo "  profile-signing extension: yes"
      else
        echo "  profile-signing extension: no"
      fi
    fi
  } >> "$work/verdicts.txt"
}

rm -f ipa/distribution-*.ipa
variant development development
variant ad-hoc ad-hoc
variant enterprise enterprise
variant app-store app-store
variant tampered-profile tampered
variant developer-signed developer-signed
variant self-signed self-signed
variant no-profile none
cp "$work/verdicts.txt" distribution-verdicts.txt
