#!/bin/sh
# The merge gate (notes/build.md): every check in order, failing fast, each
# with its wall time. Run it in the task's worktree after `git rebase main`; main is only ever
# fast-forwarded, never built. Usage: tools/gate.sh [--sweep-seeds N] [--all] [--base REV] [--plan]   (from the worktree root)
# The dev sim sweep runs every scenario at 5 seeds (scenario coverage; seed breadth is the
# 300-seed periodic check, notes/coordination.md) when the branch touches the simulator or a
# crate it has caught regressions in (core/test/sim/, osis-engine, osis-node, osis-perm, osis-crdt,
# osis-store, osis-crypto: everything the simulated nodes run on)
# or Cargo.toml/lock since its merge base with main (always on main itself);
# --sweep-seeds N forces N seeds, 0 skips.
# Per project (notes/build.md, Merge gate): the GUI workspace (libs/kit/, app/; root manifest libs/kit/Cargo.toml)
# has its own steps. A diff touching only libs/kit/ or app/ runs only the GUI steps; any other diff runs
# the core steps plus a `cargo check` of the GUI workspace (an osis API change must not silently
# break the app); both, both. On main itself, or with --all, everything runs. --base REV compares
# against REV instead of the merge base with main (to time one project's steps). --plan prints the
# selection (core, gui, seeds) and exits (tested by tools/gate_select_test.sh).
# A diff whose non-GUI paths are all Markdown under spec/, notes/ and issues/ (core=docs) runs the instant checks only (plus
# the GUI steps if it touched libs/kit/ or app/): no build, tier 1, lints, deny or sweep.
set -e
cd "$(git rev-parse --show-toplevel)"
# one gate at a time on the box: two overlapping gates each take about twice as long
if [ -z "$OSIS_GATE_LOCKED" ]; then
  echo "gate: waiting for the box-wide gate lock" >&2
  OSIS_GATE_LOCKED=1 exec flock "${XDG_RUNTIME_DIR:-/tmp}/osis-gate.lock" "$0" "$@"
fi
# a gate on a half-rebased tree passes on the wrong code (watchdog 13i: eight agents piped a
# stopped rebase into the gate)
gd=$(git rev-parse --git-dir)
if [ -d "$gd/rebase-merge" ] || [ -d "$gd/rebase-apply" ] || [ -f "$gd/MERGE_HEAD" ] || [ -n "$(git diff --name-only --diff-filter=U)" ]; then
  echo "gate: a rebase or merge is in progress or conflicts remain; finish it first" >&2; exit 2
fi
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
  # file moved out of core into libs/kit/ still selects the core steps; a name git quotes (non-ASCII,
  # control characters) starts with '"'
  changed=$(git diff --no-renames --name-only "$base" --)
  changed="$changed
$(git ls-files --others --exclude-standard)"
  printf '%s\n' "$changed" | grep -q -v -e '^"\{0,1\}libs/kit/' -e '^"\{0,1\}app/' -e '^$' || core=
  printf '%s\n' "$changed" | grep -q -e '^"\{0,1\}libs/kit/' -e '^"\{0,1\}app/' || gui=
  # docs: only Markdown under spec/, notes/, issues/, and no Rust source names a path there on a
  # line that reads or includes a file; else everything
  if [ -n "$core" ] && ! printf '%s\n' "$changed" | grep -q -v -e '^"\{0,1\}\(spec\|notes\|issues\)/.*\.md"\{0,1\}$' -e '^"\{0,1\}libs/kit/' -e '^"\{0,1\}app/' -e '^$'; then
    readers=$(git grep -n -E '(include(_str|_bytes)?!|read_to_string|fs::read|File::open|\.join)\(.*(spec|notes|issues)/' -- '*.rs' | grep -v -e '^libs/kit/' -e '^app/' || true)
    if [ -z "$readers" ]; then
      core=docs
    else
      printf 'gate: docs-only diff, but these read spec/, notes/ or issues/ (add them to the docs step): full gate\n%s\n' "$readers" >&2
    fi
  fi
fi
if [ -z "$seeds" ]; then
  seeds=5
  sweep_paths="Cargo.toml Cargo.lock core/test/sim core/engine core/node core/perm core/crdt core/store core/crypto"
  if [ -n "$base" ] && [ "$base" != "$(git rev-parse HEAD)" ] && git diff --quiet "$base" -- $sweep_paths \
      && [ -z "$(git ls-files --others --exclude-standard -- $sweep_paths)" ]; then
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
# Children's CPU seconds so far (user + system); a step prints the difference: under load wall time says little.
# `times` in the shell itself: a subshell's children start at 0.
tf=$(mktemp)
trap 'rm -f "$tf"' EXIT
cpu() { times > "$tf"; cpu=$(awk 'function s(t) { split(t, a, /[ms]/); return a[1] * 60 + a[2] } NR == 2 { printf "%d", s($1) + s($2) }' "$tf"); }
step() { printf '== %s\n' "$*"; step_s=$(date +%s); cpu; step_c=$cpu; "$@"; cpu; printf '   (%ss, %s CPU-s)\n' $(( $(date +%s) - step_s )) $(( cpu - step_c )); }
# The GUI workspace: its own target (libs/kit/target), lock and deny config.
gui_steps() {
  step python3 tools/policy.py libs/kit
  ( cd libs/kit && step cargo clippy --workspace --all-targets --locked -- -D warnings )
  ( cd libs/kit && step cargo test --workspace --locked )
  ( cd libs/kit && step cargo deny check )
}
# Both workspaces' lockfiles, in about a second: a core dependency change leaves libs/kit/Cargo.lock
# stale, which the kit's `--locked` steps would find only at the gate's end. Not `--offline`: a
# crate missing from the local cache would fail as if the lock were stale.
locks() {
  for d in . libs/kit; do
    ( cd "$d" && cargo metadata --locked --format-version 1 >/dev/null ) || {
      echo "gate: $d/Cargo.lock check failed (above); a stale lock (\"cannot update the lock file\"): refresh it with (cd $d && cargo metadata --format-version 1 >/dev/null) and commit it" >&2; return 1; }
  done
}
step locks
if [ -z "$core" ]; then
  echo "== GUI-only change: core steps skipped"
  gui_steps
  echo "== gate passed ($(( $(date +%s) - t0 ))s)"
  exit 0
fi
# instant checks first, so a missing citation fails before minutes of tests
# (policy.py and spec_map.py cover the core workspace: core/, libs/chat/, cli/; the GUI one is checked above)
step python3 tools/policy.py
step sh tools/gate_select_test.sh
step python3 tools/spec_map.py --uncited
step python3 tools/spec_map.py --gaps
if [ "$core" = docs ]; then
  [ -z "$gui" ] || gui_steps
  echo "== gate passed, docs-only change: tier 1, lints, deny and sweep skipped ($(( $(date +%s) - t0 ))s)"
  exit 0
fi
# lints before tier 1: a lint failure found after minutes of tests wasted them (watchdog 13h)
step cargo clippy --workspace --all-targets --locked -- -D warnings
step cargo clippy-net --locked -- -D warnings
step cargo test --workspace --locked
step unification_check
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
  ( cd libs/kit && step cargo check --workspace --all-targets --locked )
fi
echo "== gate passed ($(( $(date +%s) - t0 ))s)"
