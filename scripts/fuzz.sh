#!/usr/bin/env bash
# Runs every cargo-fuzz target for a time budget (AT-ARC-016): no panic, hang (10 s per input)
# or memory blow-up (2 GB) allowed. Needs a nightly toolchain and cargo-fuzz.
#   scripts/fuzz.sh            # 60 seconds per target
#   FUZZ_SECONDS=600 scripts/fuzz.sh archive apk
# A failing input is saved under fuzz/artifacts/<target>/; reproduce it with
#   cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>
set -euo pipefail
cd "$(dirname "$0")/.."

seconds="${FUZZ_SECONDS:-60}"
if [ "$#" -gt 0 ]; then
    targets=("$@")
else
    targets=(archive binary_xml protobuf_xml resource_table elf certificate dex apk bundle)
fi

for target in "${targets[@]}"; do
    # Whole packages need room; single files stay small, which keeps mutation effective.
    case "$target" in
        archive | apk | bundle) max_len=262144 ;;
        *) max_len=65536 ;;
    esac
    mkdir -p "fuzz/corpus/$target"
    echo "== $target: ${seconds}s"
    cargo +nightly fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" -- \
        -max_total_time="$seconds" -max_len="$max_len" -timeout=10 -rss_limit_mb=2048 \
        -print_final_stats=1
done
echo "fuzzed ${#targets[@]} targets for ${seconds}s each: no failures"
