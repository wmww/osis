#!/bin/sh
# The merge gate (notes/testing.md, Build hygiene), in order, failing fast; then a sweep of the
# build dir (artifacts are fresh right after the gate, so the sweep's own liveness build compiles
# nothing and only stale artifacts go). Usage: tools/gate.sh [--sweep-seeds N]   (from the repo root)
# The sim sweep (dev profile, the tests' artifacts) runs with 30 seeds when the branch touches
# osis-node, osis-perm, osis-commit, osis-crdt or the simulator since its merge base with main
# (always on main itself); --sweep-seeds N forces N seeds, 0 skips it.
set -e
seeds=
[ "$1" = "--sweep-seeds" ] && seeds=$2
if [ -z "$seeds" ]; then
  seeds=30
  base=$(git merge-base HEAD main 2>/dev/null || true)
  if [ -n "$base" ] && [ "$base" != "$(git rev-parse HEAD)" ] && git diff --quiet "$base" -- \
      crates/osis-node crates/osis-perm crates/osis-commit crates/osis-crdt sim; then
    seeds=0
  fi
fi
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
  step cargo run --locked --bin sim-sweep -- --seeds "$seeds" --budget-secs 900
else
  echo "== sim sweep skipped"
fi
step tools/sweep.sh
echo "== gate passed"
