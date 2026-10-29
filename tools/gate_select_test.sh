#!/bin/sh
# Tests tools/gate.sh step selection (--plan) on fabricated histories in a throwaway repo.
# Usage: sh tools/gate_select_test.sh   (exit 1 on any mismatch)
set -e
gate=$(cd "$(dirname "$0")" && pwd)/gate.sh
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"
git init -q -b main r
cd r
git config user.email t@t; git config user.name t; git config commit.gpgsign false
mkdir -p tools core/engine core/osis kit/src app notes
cp "$gate" tools/gate.sh
for f in Cargo.toml core/engine/a.rs core/osis/a.rs kit/src/a.rs app/a.rs notes/n.md; do
  seq 1 40 > "$f"
done
git add -A; git commit -qm init
fail=0 n=0
# check NAME EXPECTED [gate args]: runs from the current directory
check() {
  name=$1 want=$2; shift 2
  got=$(sh "$gate" --plan "$@" 2>&1) || got="exit $?: $got"
  n=$((n + 1)); if [ "$got" = "$want" ]; then :; else echo "FAIL $name: got '$got', want '$want'"; fail=1; fi
}
# case NAME EXPECTED SHELL-CMD: a fresh branch off main, the command, committed
case_() {
  git checkout -q main; git branch -qD t 2>/dev/null || true; git checkout -qb t
  sh -c "$3"; git status --porcelain | grep -q . || { echo "FAIL $1: changed nothing"; fail=1; }; git add -A; git commit -qm "$1"
  check "$1" "$2"
}
check "on main" "core=1 gui=1 seeds=5"
case_ "kit only" "core=0 gui=1 seeds=0" "echo x >> kit/src/a.rs"
case_ "app only" "core=0 gui=1 seeds=0" "echo x >> app/a.rs"
case_ "new kit file with space" "core=0 gui=1 seeds=0" "echo x > 'kit/src/b c.rs'"
case_ "new kit file, non-ASCII name" "core=0 gui=1 seeds=0" "echo x > \"kit/src/\$(printf '\\303\\251').rs\""
case_ "new app file, tab in name" "core=0 gui=1 seeds=0" "echo x > \"app/a\$(printf '\\t')b.rs\""
case_ "core, no sweep crate" "core=1 gui=0 seeds=0" "echo x >> core/osis/a.rs"
case_ "sweep crate" "core=1 gui=0 seeds=5" "echo x >> core/engine/a.rs"
case_ "root manifest" "core=1 gui=0 seeds=5" "echo x >> Cargo.toml"
case_ "notes only" "core=1 gui=0 seeds=0" "echo x >> notes/n.md"
case_ "gate itself" "core=1 gui=0 seeds=0" "echo '#' >> tools/gate.sh"
case_ "kit and core" "core=1 gui=1 seeds=0" "echo x >> kit/src/a.rs; echo x >> core/osis/a.rs"
case_ "core deleted" "core=1 gui=0 seeds=0" "git rm -q core/osis/a.rs"
case_ "core moved into kit" "core=1 gui=1 seeds=0" "git mv core/osis/a.rs kit/src/moved.rs"
case_ "sweep crate moved into app" "core=1 gui=1 seeds=5" "git mv core/engine/a.rs app/moved.rs"
check "--all" "core=1 gui=1 seeds=5" --all
check "--base HEAD" "core=1 gui=1 seeds=5" --base HEAD
check "--base bad" "exit 2: fatal: Needed a single revision" --base nonexistent
case_ "kit commit" "core=0 gui=1 seeds=0" "echo x >> kit/src/a.rs"
cd kit/src  # not a subshell: check's counters must survive
check "from a subdirectory" "core=0 gui=1 seeds=0"
cd ../..
echo x > core/osis/new.rs
cd kit/src
check "untracked core file, from a subdirectory" "core=1 gui=1 seeds=0"
cd ../..
rm core/osis/new.rs
echo x >> core/osis/a.rs
check "uncommitted core edit" "core=1 gui=1 seeds=0"
git checkout -q core/osis/a.rs
echo x > core/osis/new.rs
check "untracked core file" "core=1 gui=1 seeds=0"
rm core/osis/new.rs
echo x > core/engine/new.rs
check "untracked sweep-crate file" "core=1 gui=1 seeds=5"
rm core/engine/new.rs
git checkout -q --detach
check "detached HEAD" "core=0 gui=1 seeds=0"
git checkout -q t
git checkout -q main; git checkout -qb fresh; echo x >> kit/src/a.rs
check "uncommitted kit edit, no commits (base = HEAD)" "core=1 gui=1 seeds=5"
git checkout -q kit/src/a.rs
git checkout -q --orphan orph; git commit -qm orphan
check "no merge base" "core=1 gui=1 seeds=5"
git checkout -q t; git branch -qm main old
check "no main branch" "core=1 gui=1 seeds=5"
echo "gate selection: $n cases, $([ $fail = 0 ] && echo ok || echo FAILED)"
exit $fail
