#!/bin/sh
# The merge gate (notes/testing.md, Build hygiene), in order, failing fast; then a sweep of the
# build dir when it passes 15 GB (artifacts are fresh right after the gate, so the sweep's own
# liveness build compiles nothing). Usage: tools/gate.sh [--sweep-seeds N]   (from the repo root)
# --sweep-seeds N runs the sim sweep with N seeds (default 30; 0 skips it).
set -e
seeds=30
[ "$1" = "--sweep-seeds" ] && seeds=$2
step() { printf '== %s\n' "$*"; "$@"; }
step cargo build --workspace --all-targets --locked
step cargo test --workspace --locked
step cargo clippy --workspace --all-targets --locked -- -D warnings
step cargo clippy-net --locked -- -D warnings
step python3 tools/policy.py
step python3 tools/spec_map.py --uncited
step python3 tools/spec_map.py --gaps
step cargo deny check
if [ "$seeds" -gt 0 ]; then
  step cargo run --release --locked --bin sim-sweep -- --seeds "$seeds" --budget-secs 900
fi
dir=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; m=json.load(sys.stdin); print(m.get("build_directory") or m["target_directory"])')
kb=$(du -sk "$dir" | cut -f1)
if [ "$kb" -gt 15728640 ]; then
  echo "== build dir $((kb / 1048576)) GB > 15 GB: sweeping"
  tools/sweep.sh
fi
echo "== gate passed"
