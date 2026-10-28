#!/bin/sh
# The merge gate (notes/build.md): every check in order, failing fast, each
# with its wall time. Run it in the task's worktree after `git rebase main`; main is only ever
# fast-forwarded, never built. Usage: tools/gate.sh [--sweep-seeds N]   (from the worktree root)
# The dev sim sweep (30 seeds) runs when the branch touches the simulator or a crate it has
# caught regressions in (core/test/sim/, osis-node, osis-perm, osis-crdt) or Cargo.toml/lock since its
# merge base with main (always on main itself); --sweep-seeds N forces N seeds, 0 skips.
set -e
seeds=
case "$1" in
  "") ;;
  --sweep-seeds) case "$2" in ''|*[!0-9]*) echo "usage: $0 [--sweep-seeds N]" >&2; exit 2;; esac; seeds=$2 ;;
  *) echo "usage: $0 [--sweep-seeds N]" >&2; exit 2 ;;
esac
if [ -z "$seeds" ]; then
  seeds=30
  base=$(git merge-base HEAD main 2>/dev/null || true)
  if [ -n "$base" ] && [ "$base" != "$(git rev-parse HEAD)" ] && git diff --quiet "$base" -- \
      Cargo.toml Cargo.lock core/test/sim core/node core/perm core/crdt; then
    seeds=0
  fi
fi
t0=$(date +%s)
step() { printf '== %s\n' "$*"; s=$(date +%s); "$@"; printf '   (%ss)\n' $(( $(date +%s) - s )); }
step cargo test --workspace --locked
step cargo clippy --workspace --all-targets --locked -- -D warnings
step cargo clippy-net --locked -- -D warnings
step python3 tools/policy.py
step python3 tools/spec_map.py --uncited
step python3 tools/spec_map.py --gaps
step sh -c 'for f in schema/*.osis; do printf "%s: " "$f"; cargo run --locked --quiet --bin osis -- schema check "$f" || exit 1; done'
step cargo deny check
if [ "$seeds" -gt 0 ]; then
  step cargo run --locked --bin sim-sweep -- --seeds "$seeds" --budget-secs 900
else
  echo "== sim sweep skipped (no sweep-relevant change since main)"
fi
echo "== gate passed ($(( $(date +%s) - t0 ))s)"
