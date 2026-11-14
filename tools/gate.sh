#!/bin/sh
# The merge gate (notes/gate.md: steps, selection, summary, exit codes).
# Usage: tools/gate.sh [--all] [--base REV] [--plan]   (from the worktree root, after
# `git fetch && git rebase origin/main`; never under tools/heavy: it takes the lock itself)
# Exit 0 passed, 3 only KNOWN failures, 1 a NEW one, 2 bad use or refused. The checks before the
# tests fail fast; every test stage runs to its end. --plan prints the step selection (tested by
# tools/gate_select_test.sh).
set -e
tools=$(cd "$(dirname "$0")" && pwd)
cd "$(git rev-parse --show-toplevel)"
# a gate on a half-rebased tree passes on the wrong code
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
# reading stdin would eat the held runner's later lines. A stage of default tests (held to the
# `test` limit) runs under tools/test_watch.py, which stops a target where no test finishes for a
# multiple of that limit and names its running tests "hung" (notes/gate.md, Hung tests).
tested() {
  local n log s c; n=$1; log=$2; shift 2
  printf '== %s\n' "$*"; s=$(date +%s); cpu; c=$cpu
  case $n in default-tests|gate.gui-tests) set -- python3 "$tools/test_watch.py" "$@" ;; esac
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
# origin's main, fetched: the base of the selection and what HEAD must contain. Local main lags (the
# coordinators push from worktrees): diffing against it counts other branches' merged work as this one's.
if git remote get-url origin > /dev/null 2>&1; then
  timeout 60 git fetch -q origin main 2>/dev/null || echo "gate: fetching origin main failed; using the last fetched one" >&2
fi
om=$(git rev-parse -q --verify refs/remotes/origin/main || true)
[ -n "$base" ] || [ -z "$om" ] || base=$(git merge-base HEAD "$om" 2>/dev/null || true)
core=1
gui=1
unify=1
every=1
doc=
if [ -z "$all" ] && [ -n "$base" ] && [ "$base" != "$(git rev-parse HEAD)" ]; then
  every=
  # the steps the paths changed since the merge base (committed or not) select: core= gui= unify= doc=
  paths=$(python3 "$tools/gate_paths.py" "$base") || exit 2
  eval "$paths"
fi
# what tools/test_select.py selects from: every crate when everything runs, else the diff from base
if [ "$core" != 1 ]; then
  select=none
elif [ -n "$every" ]; then
  select=all
else
  select=diff
fi
if [ -n "$plan" ]; then echo "core=${core:-0} gui=${gui:-0} unify=${unify:-0} select=$select${doc:+ doc=$doc}"; exit 0; fi
# a branch not on origin's main gates code other than what merges: refuse it
if [ -n "$om" ] && ! git merge-base --is-ancestor "$om" HEAD; then
  echo "gate: HEAD does not contain origin/main ($(git rev-list --count "HEAD..$om") commits behind): git rebase origin/main" >&2; exit 2
fi
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
# SCHED_IDLE: builds then crawl 10-20x beside any test run (notes/build.md, Profile and command forms)
if systemctl is-active --quiet com.system76.Scheduler.service 2>/dev/null; then
  echo "gate: WARNING: system76-scheduler is running; builds here run at idle priority and take many times their cost (notes/build.md)" >&2
fi
t0=$(date +%s)
# the selection (`run` lines: the test stages expected) and every test stage's result
sel=$tmp/sel
results=$sel.res
# The whole gate against its limit (`gate`), its lock wait (seconds, $1) left out, naming each
# stage over its share when over; then every test stage's failure, KNOWN or NEW, and the pass
# line or the summary's exit.
passed() {
  cpu
  python3 "$tools/limits.py" check gate "$cpu" $(( $(date +%s) - t0 - $1 )) --since "$t0" || true
  # once a stage is expected (`$sel` exists), the summary decides: a hold that never ran (a
  # refused or failed tools/heavy) leaves its stages unrun, which the summary counts NEW
  if [ -e "$sel" ] || [ -e "$results" ]; then
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
gui_test() { echo "expect gate.gui-tests" >> "$sel"; tested gate.gui-tests "$tmp/gui.log" cargo test $gui_pkgs --locked --no-fail-fast; }
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
  step python3 tools/gate_paths_test.py
  step python3 tools/limits_test.py
  step python3 tools/doc_refs_test.py
  step python3 tools/policy_test.py
  step python3 tools/limits.py split
  step python3 tools/spec_map.py --uncited --gaps
}
limited gate.checks instant
if [ "$core" = docs ]; then
  if [ -n "$gui" ]; then gui_only "docs and GUI change"; fi
  passed 0 ", docs-only change: builds, tests, lints and deny skipped"
  exit 0
fi
# comments only: no test reads one; clippy catches a comment that broke the code, the doctests a
# changed doc comment's example
if [ "$core" = comments ]; then
  limited gate.clippy cargo clippy --all-targets --locked -- -D warnings
  if [ -n "$doc" ]; then
    echo "expect gate.doctests" >> "$sel"
    # shellcheck disable=SC2046
    tested gate.doctests "$tmp/doc.log" cargo test --doc --locked --no-fail-fast $(printf -- '-p %s ' $doc)
  fi
  if [ -n "$gui" ]; then gui_only "comments and GUI change"; fi
  passed 0 ", comments-only change: builds, tests but doctests, and deny skipped"
  exit 0
fi
# the tests the gate runs, as `build CMD` and `run CMD` lines: the default tests, then the branch's
# selection (properties and sim scenarios at small size, on one random offset)
printf '%s\n' "build cargo test --locked --no-fail-fast --no-run" "run default-tests cargo test --locked --no-fail-fast" > "$sel"
offset=$(python3 -c 'import random; print(random.randrange(10**12))')
if [ "$select" = all ]; then from=--all; else from="--base $base"; fi
# shellcheck disable=SC2086
step python3 tools/test_select.py $from --offset "$offset" --emit "$sel"
# lints before tests: a lint failure found after minutes of tests wastes them;
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
  echo "== unification check skipped (no Cargo.toml, Cargo.lock or .cargo/ change since origin/main)"
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
