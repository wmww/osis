#!/bin/sh
# The merge gate (notes/build.md): every check in order, failing fast, each
# with its wall time. Run it in the task's worktree after `git rebase main`; main is only ever
# fast-forwarded, never built. Usage: tools/gate.sh [--sweep-seeds N] [--all] [--base REV] [--plan]   (from the worktree root)
# The dev sim sweep runs every scenario at 5 seeds (scenario coverage; seed breadth is the
# 300-seed periodic check, notes/coordination.md) when the branch touches the simulator or a
# crate it has caught regressions in (core/test/sim/, osis-engine, osis-node, osis-perm, osis-crdt)
# or Cargo.toml/lock since its merge base with main (always on main itself);
# --sweep-seeds N forces N seeds, 0 skips.
# Per project (notes/build.md, Merge gate): the GUI workspace (kit/, app/; root manifest kit/Cargo.toml)
# has its own steps. A diff touching only kit/ or app/ runs only the GUI steps; any other diff runs
# the core steps plus a `cargo check` of the GUI workspace (an osis API change must not silently
# break the app); both, both. On main itself, or with --all, everything runs. --base REV compares
# against REV instead of the merge base with main (to time one project's steps). --plan prints the
# selection (core, gui, seeds) and exits (tested by tools/gate_select_test.sh).
set -e
cd "$(git rev-parse --show-toplevel)"
seeds=
all=
base=
plan=
while [ $# -gt 0 ]; do
  case "$1" in
    --sweep-seeds) case "$2" in ''|*[!0-9]*) echo "usage: $0 [--sweep-seeds N] [--all] [--base REV] [--plan]" >&2; exit 2;; esac; seeds=$2; shift 2 ;;
    --all) all=1; shift ;;
    --plan) plan=1; shift ;;
    --base) base=$(git rev-parse --verify "$2^{commit}") || exit 2; shift 2 ;;
    *) echo "usage: $0 [--sweep-seeds N] [--all] [--base REV] [--plan]" >&2; exit 2 ;;
  esac
done
[ -n "$base" ] || base=$(git merge-base HEAD main 2>/dev/null || true)
core=1
gui=1
if [ -z "$all" ] && [ -n "$base" ] && [ "$base" != "$(git rev-parse HEAD)" ]; then
  # changed paths since the merge base, committed or not; a rename counts as delete + add, so a
  # file moved out of core into kit/ still selects the core steps
  changed=$(git diff --no-renames --name-only "$base" --)
  changed="$changed
$(git ls-files --others --exclude-standard)"
  printf '%s\n' "$changed" | grep -q -v -e '^kit/' -e '^app/' -e '^$' || core=
  printf '%s\n' "$changed" | grep -q -e '^kit/' -e '^app/' || gui=
fi
if [ -z "$seeds" ]; then
  seeds=5
  if [ -n "$base" ] && [ "$base" != "$(git rev-parse HEAD)" ] && git diff --quiet "$base" -- \
      Cargo.toml Cargo.lock core/test/sim core/engine core/node core/perm core/crdt; then
    seeds=0
  fi
fi
if [ -n "$plan" ]; then echo "core=${core:-0} gui=${gui:-0} seeds=$seeds"; exit 0; fi
t0=$(date +%s)
# Feature unification is selection-invariant (notes/build.md, Feature unification): after the
# whole-workspace build, building any one member alone compiles nothing.
unification_check() {
  cargo build --workspace --all-targets --locked --quiet
  bad=0
  for p in $(cargo metadata --no-deps --format-version 1 --locked | python3 -c 'import json, sys; print(" ".join(p["name"] for p in json.load(sys.stdin)["packages"]))'); do
    out=$(cargo build -p "$p" --all-targets --locked 2>&1) || { printf '%s\n' "$out"; return 1; }
    c=$(printf '%s\n' "$out" | sed -n 's/^ *Compiling \([^ ]*\).*/\1/p' | tr '\n' ' ')
    [ -z "$c" ] || { echo "   $p alone compiles: $c"; bad=$((bad + 1)); }
  done
  echo "   $bad offenders"
  [ "$bad" -eq 0 ]
}
step() { printf '== %s\n' "$*"; s=$(date +%s); "$@"; printf '   (%ss)\n' $(( $(date +%s) - s )); }
# The GUI workspace: its own target (kit/target), lock and deny config.
gui_steps() {
  step python3 tools/policy.py kit
  ( cd kit && step cargo test --workspace --locked )
  ( cd kit && step cargo clippy --workspace --all-targets --locked -- -D warnings )
  ( cd kit && step cargo deny check )
}
if [ -z "$core" ]; then
  echo "== GUI-only change: core steps skipped"
  gui_steps
  echo "== gate passed ($(( $(date +%s) - t0 ))s)"
  exit 0
fi
# instant checks first, so a missing citation fails before minutes of tests
# (policy.py and spec_map.py cover the core workspace: core/, cli/; the GUI one is checked above)
step python3 tools/policy.py
step sh tools/gate_select_test.sh
step python3 tools/spec_map.py --uncited
step python3 tools/spec_map.py --gaps
step cargo test --workspace --locked
step unification_check
step cargo clippy --workspace --all-targets --locked -- -D warnings
step cargo clippy-net --locked -- -D warnings
step sh -c 'for f in schema/*.osis; do printf "%s: " "$f"; cargo run --locked --quiet --bin osis -- schema check "$f" || exit 1; done'
step cargo deny check
if [ "$seeds" -gt 0 ]; then
  step cargo run --locked --bin sim-sweep -- --seeds "$seeds" --budget-secs 900
else
  echo "== sim sweep skipped (no sweep-relevant change since main)"
fi
if [ -n "$gui" ]; then
  gui_steps
else
  ( cd kit && step cargo check --workspace --all-targets --locked )
fi
echo "== gate passed ($(( $(date +%s) - t0 ))s)"
