#!/bin/sh
# tools/sweep-target.py plus osis's other canonical shapes (notes/testing.md, Build hygiene):
# both clippy runs, and `cargo test-net` only if its artifacts are there.
# Usage: tools/sweep.sh [--dry-run]   (from the repo root)
set -e
dir=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; m=json.load(sys.stdin); print(m.get("build_directory") or m["target_directory"])')
set -- --also "clippy --workspace --all-targets -- -D warnings" --also "clippy-net -- -D warnings" "$@"
ls "$dir"/release/deps/libiroh_relay-*.rlib >/dev/null 2>&1 && set -- --also "test-net --no-run" "$@"
exec python3 "$(dirname "$0")/sweep-target.py" "$@"
