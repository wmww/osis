#!/bin/sh
# The merge gate (notes/build.md, Merge gate; notes/testing.md, The gate): every check in order,
# each with its wall time and CPU-s. The checks before the tests (instant checks, lints, builds,
# deny) fail fast; every test stage runs to its end whatever an earlier one did, and the gate then
# prints every failure, KNOWN (tools/known_failures.txt) or NEW (tools/gate_failures.py). Exit 0
# on a pass, 3 when only KNOWN failures failed, 1 on a NEW one, 2 on bad use. Run it in the task's
# worktree after `git rebase main`; main is only ever fast-forwarded, never built.
# Usage: tools/gate.sh [--all] [--base REV] [--plan]   (from the worktree root)
# Its tests: the default tests (`cargo test`) plus the branch's selection from tools/test_select.py
# (properties and sim scenarios at small size, from the crates the branch touched and their
# dependents), all run in one hold of the heavy lock; every build and lint before it runs unlocked.
# Per project (notes/build.md, Components pay for themselves): the GUI (osis-kit libs/kit/, osis-app
# app/, osis-android app/android/: workspace members outside default-members) has its own steps. A
# diff touching only libs/kit/ or app/ runs only the GUI steps; any other diff runs the core steps,
# whose lint covers the GUI too (an osis API change must not silently break the app); both, both. The
# unification check runs when a Cargo.toml, Cargo.lock or .cargo/ changed. On main itself, with no
# merge base, or with --all, everything runs and the selection is every crate. --base REV compares
# against REV instead of the merge base with main. --plan prints the step selection (core, gui,
# unify, select: all, diff or none) and exits (tested by tools/gate_select_test.sh); the tests a
# `select=diff` picks: tools/test_select.py [--base REV].
# A diff whose non-GUI paths are all Markdown under spec/, notes/ and issues/ (core=docs) runs the
# instant checks only (plus the GUI steps if it touched libs/kit/ or app/): no build, tests, lints or deny.
set -e
tools=$(cd "$(dirname "$0")" && pwd)
cd "$(git rev-parse --show-toplevel)"
# a gate on a half-rebased tree passes on the wrong code (watchdog 13i: eight agents piped a
# stopped rebase into the gate)
gd=$(git rev-parse --git-dir)
if [ -d "$gd/rebase-merge" ] || [ -d "$gd/rebase-apply" ] || [ -f "$gd/MERGE_HEAD" ] || [ -n "$(git diff --name-only --diff-filter=U)" ]; then
  echo "gate: a rebase or merge is in progress or conflicts remain; finish it first" >&2; exit 2
fi
held=
all=
base=
plan=
while [ $# -gt 0 ]; do
  case "$1" in
    --held) held=$2; shift 2 ;;
    --all) all=1; shift ;;
    --plan) plan=1; shift ;;
    --base) base=$(git rev-parse --verify "$2^{commit}") || exit 2; shift 2 ;;
    *) echo "usage: $0 [--all] [--base REV] [--plan]" >&2; exit 2 ;;
  esac
done
# Children's CPU seconds so far (user + system); a step prints the difference: under load wall time says little.
# `times` in the shell itself: a subshell's children start at 0.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tf=$tmp/times
cpu() { times > "$tf"; cpu=$(awk 'function s(t) { split(t, a, /[ms]/); return a[1] * 60 + a[2] } NR == 2 { printf "%d", s($1) + s($2) }' "$tf"); }
step() {
  printf '== %s\n' "$*"; local s c; s=$(date +%s); cpu; c=$cpu; "$@"; cpu
  step_wall=$(( $(date +%s) - s )); step_cpu=$(( cpu - c )); printf '   (%ss, %s CPU-s)\n' $step_wall $step_cpu
}
# A step with time limits (notes/build.md, Time limits): over one prints a `LIMIT` line and logs
# the hit; it never fails the gate.
limited() { local n; n=$1; shift; step "$@"; python3 "$tools/limits.py" check "$n" $step_cpu $step_wall || true; }
# A test stage, `tested LIMIT LOG CMD...` (one external command): timed and checked against its
# limit like `limited`, its output also saved to LOG, and `LIMIT EXIT LOG` appended to $results;
# it returns 0 whatever CMD did, so no failure ends a later stage. Its stdin is /dev/null: one
# reading stdin would eat the held runner's later lines.
tested() {
  local n log s c; n=$1; log=$2; shift 2
  printf '== %s\n' "$*"; s=$(date +%s); cpu; c=$cpu
  { rc=0; "$@" < /dev/null || rc=$?; echo "$rc" > "$log.rc"; } 2>&1 | tee "$log"
  cpu; step_wall=$(( $(date +%s) - s )); step_cpu=$(( cpu - c )); printf '   (%ss, %s CPU-s)\n' $step_wall $step_cpu
  python3 "$tools/limits.py" check "$n" $step_cpu $step_wall || true
  echo "$n $(cat "$log.rc") $log" >> "$results"
}
# Inside the one heavy-lock hold (the tests step at the end): each `run LIMIT CMD` line of the
# selection file SEL as a test stage, every one run; results in SEL.res, logs SEL.N.log; exits 1
# if any failed. Internal: the gate calls itself this way under tools/heavy, which sets
# HEAVY_HELD; without it this would run the tests unlocked.
if [ -n "$held" ]; then
  [ -n "$HEAVY_HELD" ] || { echo "gate: --held is internal: only the gate's tools/heavy hold runs it" >&2; exit 2; }
  results=$held.res
  : > "$results"
  i=0
  while IFS= read -r l; do
    case "$l" in "run "*) l=${l#run }; i=$((i + 1)); tested "${l%% *}" "$held.$i.log" sh -c "${l#* }" ;; esac
  done < "$held"
  awk '$2 != 0 { f = 1 } END { exit f }' "$results"
  exit
fi
[ -n "$base" ] || base=$(git merge-base HEAD main 2>/dev/null || true)
core=1
gui=1
unify=1
every=1
if [ -z "$all" ] && [ -n "$base" ] && [ "$base" != "$(git rev-parse HEAD)" ]; then
  every=
  # changed paths since the merge base, committed or not; a rename counts as delete + add, so a
  # file moved out of core into libs/kit/ still selects the core steps; a name git quotes (non-ASCII,
  # control characters) starts with '"'
  changed=$(git diff --no-renames --name-only "$base" --)
  changed="$changed
$(git ls-files --others --exclude-standard)"
  printf '%s\n' "$changed" | grep -q -v -e '^"\{0,1\}libs/kit/' -e '^"\{0,1\}app/' -e '^$' || core=
  printf '%s\n' "$changed" | grep -q -e '^"\{0,1\}libs/kit/' -e '^"\{0,1\}app/' || gui=
  # what decides feature resolution: any manifest, the lock, cargo's config
  printf '%s\n' "$changed" | grep -q -e '^"\{0,1\}\(.*/\)\{0,1\}Cargo\.toml"\{0,1\}$' -e '^"\{0,1\}Cargo\.lock"\{0,1\}$' -e '^"\{0,1\}\.cargo/' || unify=
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
# what tools/test_select.py selects from: every crate when everything runs, else the diff from base
if [ "$core" != 1 ]; then
  select=none
elif [ -n "$every" ]; then
  select=all
else
  select=diff
fi
if [ -n "$plan" ]; then echo "core=${core:-0} gui=${gui:-0} unify=${unify:-0} select=$select"; exit 0; fi
# Feature unification is selection-invariant (notes/build.md, Feature unification): after the
# whole-workspace build (GUI included), building the default members, or any one member alone,
# compiles nothing.
unification_check() {
  cargo build --workspace --all-targets --locked --quiet
  bad=0
  for p in '' $(cargo metadata --no-deps --format-version 1 --locked | python3 -c 'import json, sys; print(" ".join(p["name"] for p in json.load(sys.stdin)["packages"]))'); do
    out=$(cargo build ${p:+-p "$p"} --all-targets --locked 2>&1) || { printf '%s\n' "$out"; return 1; }
    c=$(printf '%s\n' "$out" | sed -n 's/^ *Compiling \([^ ]*\).*/\1/p' | tr '\n' ' ')
    [ -z "$c" ] || { echo "   ${p:-the default members} alone compiles: $c"; bad=$((bad + 1)); }
  done
  echo "   $bad offenders"
  [ "$bad" -eq 0 ]
}
# system76-scheduler puts any cargo it sees (60 s refresh) and everything it spawns after in
# SCHED_IDLE: builds then crawl 10-20x beside any test run (notes/build.md, Scheduler)
if systemctl is-active --quiet com.system76.Scheduler.service 2>/dev/null; then
  echo "gate: WARNING: system76-scheduler is running; builds here run at idle priority and take many times their cost (notes/build.md)" >&2
fi
t0=$(date +%s)
# the selection (`run` lines: the test stages expected) and every test stage's result
sel=$tmp/sel
results=$sel.res
# The whole gate against its limit (`gate`), its lock wait (seconds, $1) left out; then every test
# stage's failure, KNOWN or NEW, and the pass line or the summary's exit.
passed() {
  cpu
  python3 "$tools/limits.py" check gate "$cpu" $(( $(date +%s) - t0 - $1 )) || true
  if [ -e "$results" ]; then
    rc=0; python3 "$tools/gate_failures.py" "$sel" "$results" || rc=$?
    [ "$rc" = 0 ] || exit "$rc"
  fi
  echo "== gate passed$2 ($(( $(date +%s) - t0 ))s)"
}
# The GUI packages: built, linted and tested only when named (not default members). Every lint
# and build here reuses core's artifacts for the core crates (Feature unification).
gui_pkgs="-p osis-kit -p osis-app -p osis-android"
# shellcheck disable=SC2086
gui_lint() { limited gate.gui-lint cargo clippy $gui_pkgs --all-targets --locked -- -D warnings; }
# shellcheck disable=SC2086
gui_test() { tested gate.gui-tests "$tmp/gui.log" cargo test $gui_pkgs --locked; }
# A change of the GUI and docs alone: no core build or test. Called from `if` bodies only: in an
# `a || f` list `set -e` is off inside f.
gui_only() {
  gui_lint
  gui_test
  if [ -n "$unify" ]; then limited gate.unify unification_check; fi
  limited gate.deny cargo deny check
  passed 0 ", $1: core build and tests skipped"
  exit 0
}
# The lockfile, in about a second, so a stale one fails here rather than at the first `--locked`
# build. Not `--offline`: a crate missing from the local cache would fail as if the lock were stale.
locks() {
  cargo metadata --locked --format-version 1 >/dev/null || {
    echo "gate: Cargo.lock check failed (above); a stale lock (\"cannot update the lock file\"): refresh it with cargo metadata --format-version 1 >/dev/null and commit it" >&2; return 1; }
}
step locks
step python3 tools/policy.py
if [ -z "$core" ]; then gui_only "GUI-only change"; fi
# instant checks first, so a missing citation fails before minutes of tests
instant() {
  step sh tools/gate_select_test.sh
  step python3 tools/test_select_test.py
  step python3 tools/gate_failures_test.py
  step python3 tools/spec_map.py --uncited
  step python3 tools/spec_map.py --gaps
}
limited gate.checks instant
if [ "$core" = docs ]; then
  if [ -n "$gui" ]; then gui_only "docs and GUI change"; fi
  passed 0 ", docs-only change: builds, tests, lints and deny skipped"
  exit 0
fi
# the tests the gate runs, as `build CMD` and `run CMD` lines: the default tests, then the branch's
# selection (properties and sim scenarios at small size, on one random offset)
printf '%s\n' "build cargo test --locked --no-fail-fast --no-run" "run default-tests cargo test --locked --no-fail-fast" > "$sel"
offset=$(python3 -c 'import random; print(random.randrange(10**12))')
if [ "$select" = all ]; then from=--all; else from="--base $base"; fi
# shellcheck disable=SC2086
step python3 tools/test_select.py $from --offset "$offset"
# shellcheck disable=SC2086
python3 tools/test_select.py --emit $from --offset "$offset" >> "$sel"
# lints before tests: a lint failure found after minutes of tests wasted them (watchdog 13h);
# core's, then the GUI's on the same artifacts (the core crates are linted already)
limited gate.clippy cargo clippy --all-targets --locked -- -D warnings
gui_lint
# every binary the tests run, built unlocked with the runs' own cargo arguments, so the hold only runs
builds() {
  while IFS= read -r l; do
    case "$l" in "build "*) step sh -c "${l#build }" < /dev/null ;; esac
  done < "$sel"
}
limited build builds
if [ -n "$unify" ]; then
  limited gate.unify unification_check
else
  echo "== unification check skipped (no Cargo.toml, Cargo.lock or .cargo/ change since main)"
fi
deny() {
  step sh -c 'for f in schema/*.osis; do printf "%s: " "$f"; cargo run --locked --quiet --bin osis -- schema check "$f" || exit 1; done'
  step cargo deny check
  # duplicates in core's graph alone: deny.toml's GUI skip-trees would hide a core duplicate that
  # has one copy in the GUI stack (their roots are absent here, so their warnings are allowed)
  step cargo deny --exclude osis-kit --exclude osis-app --exclude osis-android check bans -A unmatched-skip-root
}
limited gate.deny deny
# The tests, in one hold of the box-wide heavy lock (tools/heavy, notes/build.md, Heavy lock): two
# all-core runs at once each take about twice as long. Doctests compile inside it, at run time.
# tools/heavy checks the hold against `gate.hold` and writes its lock wait to $wf, which the
# gate's own limit leaves out.
# A failing stage ends neither the hold nor the gate: the GUI tests still run, then the summary.
wf=$tmp/wait
export HEAVY_WAIT_FILE="$wf"
step tools/heavy --limit gate.hold sh tools/gate.sh --held "$sel" || :
wait_s=$(cat "$wf" 2>/dev/null || true); wait_s=${wait_s:-0}
if [ -n "$gui" ]; then gui_test; fi
passed "${wait_s%.*}" ", ${wait_s%.*}s of it waiting for the heavy lock"
