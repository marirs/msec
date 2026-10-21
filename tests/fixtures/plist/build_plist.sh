#!/bin/sh
# Rebuilds the plist fixtures and Apple's view of them:
# - xml/*.xml, binary/*.bplist and openstep/*.strings: from make_plist_fixtures.py, one rule of
#   Core Foundation's readers per file;
# - binary/info.bplist and binary/types.bplist: plutil's binary conversion of xml/info.xml and
#   xml/types.xml, the format Xcode writes Info.plist in;
# - verdicts.txt: whether plutil (Core Foundation) reads each file, and its error when not;
# - expected/<file>.xml: what plutil writes for each file it reads (`plutil -convert xml1`),
#   unless it cannot write the content as XML. The depth-* files are about where reading stops,
#   so their (large) XML is not kept.
# Needs macOS (plutil) and python3. Run from anywhere.
set -eu
cd "$(dirname "$0")"
rm -rf xml binary openstep expected
python3 -I make_plist_fixtures.py .
plutil -convert binary1 -o binary/info.bplist xml/info.xml
plutil -convert binary1 -o binary/types.bplist xml/types.xml
mkdir expected
for file in xml/*.xml binary/*.bplist openstep/*.strings; do
  if plutil -lint "$file" > /dev/null 2>&1; then
    echo "$file: accepted"
    case "$file" in */depth-*) continue ;; esac
    plutil -convert xml1 -o "expected/$(basename "$file").xml" "$file" 2> /dev/null ||
      rm -f "expected/$(basename "$file").xml"
  else
    # plutil's message, without the file name and the JSON parser's own complaint.
    message=$(plutil -lint "$file" 2>&1 | head -n 1 | sed -e "s|^$file: ||" -e 's| / JSON error.*||' |
      sed -e 's| around line .*||' | cut -c 1-160)
    echo "$file: rejected: $message"
  fi
done > verdicts.txt
