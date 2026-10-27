#!/bin/sh
# tools/sweep-target.py over osis's canonical shapes (notes/testing.md, Build hygiene), all dev:
# the build, both clippy runs, and `cargo test-net` only if its artifacts are there. release/
# (benches only) is left alone: delete it after a bench.
# Usage: tools/sweep.sh [--dry-run]   (from the repo root)
set -e
dir=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; m=json.load(sys.stdin); print(m.get("build_directory") or m["target_directory"])')
set -- --no-defaults --also "build --workspace --all-targets" --also "clippy --workspace --all-targets -- -D warnings" --also "clippy-net -- -D warnings" "$@"
ls "$dir"/debug/deps/libiroh_relay-*.rlib >/dev/null 2>&1 && set -- --also "test-net --no-run" "$@"
exec python3 "$(dirname "$0")/sweep-target.py" "$@"
