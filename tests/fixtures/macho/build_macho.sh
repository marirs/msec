#!/bin/sh
# Rebuilds msec's Mach-O fixtures (bin/) and Apple's reading of each (oracle/):
# - bin/hardened: Objective-C under ARC, stack protector, stripped, ad-hoc signed with
#   entitlements (codesign); bin/hardened-arm64e and bin/universal (lipo of both);
# - bin/plain (C, linker-signed only), bin/no-canary (-fno-stack-protector), bin/manual (manual
#   reference counting), bin/debug (not stripped: a debug map in the symbol table), bin/library
#   (a dylib), bin/swift, bin/unsigned (signature removed);
# - bin/encrypted (hardened with cryptid set to 1), bin/tampered (one code byte changed after
#   signing), bin/stack-exec (MH_ALLOW_STACK_EXECUTION set) and bin/no-pie (MH_PIE cleared),
#   made by make_macho_fixtures.py, which also writes the hostile files in hostile/;
# - oracle/<name>.otool.txt (otool -arch all -l), .nm.txt (nm -u, and the debug-entry count
#   from nm -ap),
#   .codesign.txt (codesign -dvvv, its verdict from codesign --verify, entitlements from
#   codesign -d --entitlements - --xml) and, for universal files, .lipo.txt (lipo -detailed_info).
#   For hostile files, oracle/hostile.txt records whether llvm-objdump (LLVM's strict Mach-O
#   reader) and codesign accept each one; those are tools, not the kernel's loader, which
#   cannot run iOS binaries here.
# Needs macOS with Xcode (an iOS SDK) and python3.
set -eu
cd "$(dirname "$0")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
cc() { xcrun --sdk iphoneos clang -target arm64-apple-ios17.0 -isysroot "$sdk" "$@"; }
sign() { codesign -s - -f --timestamp=none "$@" > /dev/null 2>&1; }

rm -rf bin hostile oracle
mkdir bin hostile oracle

cc -Os -fobjc-arc -fstack-protector-strong -framework Foundation -o bin/hardened sources/hardened.m
xcrun strip -x bin/hardened
sign --entitlements sources/entitlements.plist bin/hardened
xcrun --sdk iphoneos clang -target arm64e-apple-ios17.0 -isysroot "$sdk" -Os -fobjc-arc \
  -fstack-protector-strong -framework Foundation -o bin/hardened-arm64e sources/hardened.m
xcrun strip -x bin/hardened-arm64e
sign --entitlements sources/entitlements.plist bin/hardened-arm64e
xcrun lipo -create bin/hardened bin/hardened-arm64e -output bin/universal

cc -Os -fstack-protector-strong -o bin/plain sources/plain.c
cc -Os -fno-stack-protector -o bin/no-canary sources/plain.c
sign bin/no-canary
cc -Os -fno-objc-arc -fno-objc-convert-messages-to-runtime-calls -framework Foundation \
  -o bin/manual sources/manual.m
sign bin/manual
cc -g -O0 -c -o "$work/debug.o" sources/plain.c
cc -g -o bin/debug "$work/debug.o"
sign bin/debug
cc -Os -dynamiclib -install_name @rpath/Library.framework/Library \
  -Wl,-rpath,@loader_path/Frameworks -o bin/library sources/library.c
sign bin/library
xcrun --sdk iphoneos swiftc -target arm64-apple-ios17.0 -sdk "$sdk" -Osize -o bin/swift \
  sources/swift.swift
sign bin/swift
cp bin/hardened bin/unsigned
codesign --remove-signature bin/unsigned

python3 -I make_macho_fixtures.py bin hostile
# Header flags today's linker no longer sets (ld dropped -allow_stack_execute, and arm64 is
# always PIE): set and cleared by make_macho_fixtures.py, then signed again.
sign bin/stack-exec
sign bin/no-pie

# Apple's reading of every fixture, without file paths (they would change with the checkout).
for file in bin/*; do
  name="$(basename "$file")"
  otool -arch all -l "$file" | sed '1d' > "oracle/$name.otool.txt"
  {
    echo "# nm -u"
    xcrun nm -u "$file" 2> /dev/null || true
    # ld64 marks every image with an N_OPT entry (radr://5614542); it is not debug information.
    echo "# debug entries (nm -ap, type -, except OPT)"
    xcrun nm -ap "$file" 2> /dev/null | awk '$2 == "-" && $5 != "OPT"' | wc -l | tr -d ' '
  } > "oracle/$name.nm.txt"
  {
    codesign -dvvv "$file" 2>&1 | grep -v '^Executable=' || true
    if codesign --verify "$file" > /dev/null 2>&1; then
      echo "verify: valid"
    else
      echo "verify: $(codesign --verify "$file" 2>&1 | sed 's|^[^:]*: ||' | head -n 1)"
    fi
    echo "# entitlements"
    codesign -d --entitlements - --xml "$file" 2> /dev/null || true
    echo
  } > "oracle/$name.codesign.txt"
  if xcrun lipo -info "$file" 2> /dev/null | grep -q '^Architectures in the fat file'; then
    xcrun lipo -detailed_info "$file" | sed '1s|.*|Fat header|' > "oracle/$name.lipo.txt"
  fi
done
for file in hostile/*; do
  name="$(basename "$file")"
  # LLVM's Mach-O reader is strict about structure and names each error; otool-classic prints
  # most of them as notes and succeeds.
  if xcrun llvm-objdump --macho --private-headers "$file" > /dev/null 2> "$work/log"; then
    objdump_verdict="reads"
  else
    objdump_verdict="refuses: $(sed -e "s|^.*'$file': ||" -e 's|^.*error: ||' "$work/log" | head -n 1 | cut -c 1-140)"
  fi
  if codesign --verify "$file" > /dev/null 2>&1; then
    codesign_verdict="valid"
  else
    codesign_verdict="$(codesign --verify "$file" 2>&1 | sed "s|$file: ||" | head -n 1 | cut -c 1-120)"
  fi
  echo "$name: llvm-objdump $objdump_verdict; codesign $codesign_verdict"
done > oracle/hostile.txt
