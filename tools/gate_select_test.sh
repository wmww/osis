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
mkdir -p tools core/engine core/osis libs/kit/src libs/chat app notes spec issues
cp "$gate" tools/gate.sh
for f in Cargo.toml core/engine/a.rs core/osis/a.rs libs/kit/src/a.rs libs/chat/a.rs app/a.rs notes/n.md spec/s.md issues/i.md; do
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
check "on main" "core=1 gui=1 unify=1 select=all"
case_ "kit only" "core=0 gui=1 unify=0 select=none" "echo x >> libs/kit/src/a.rs"
case_ "libs/chat is core" "core=1 gui=0 unify=0 select=diff" "echo x >> libs/chat/a.rs"
case_ "app only" "core=0 gui=1 unify=0 select=none" "echo x >> app/a.rs"
case_ "new kit file with space" "core=0 gui=1 unify=0 select=none" "echo x > 'libs/kit/src/b c.rs'"
case_ "new kit file, non-ASCII name" "core=0 gui=1 unify=0 select=none" "echo x > \"libs/kit/src/\$(printf '\\303\\251').rs\""
case_ "new app file, tab in name" "core=0 gui=1 unify=0 select=none" "echo x > \"app/a\$(printf '\\t')b.rs\""
case_ "core crate" "core=1 gui=0 unify=0 select=diff" "echo x >> core/osis/a.rs"
case_ "root manifest" "core=1 gui=0 unify=1 select=diff" "echo x >> Cargo.toml"
case_ "lockfile" "core=1 gui=0 unify=1 select=diff" "echo x > Cargo.lock"
case_ "member manifest" "core=1 gui=0 unify=1 select=diff" "echo x > core/osis/Cargo.toml"
case_ "kit manifest" "core=0 gui=1 unify=1 select=none" "echo x > libs/kit/Cargo.toml"
case_ "cargo config" "core=1 gui=0 unify=1 select=diff" "mkdir .cargo; echo x > .cargo/config.toml"
case_ "a file ending in Cargo.toml" "core=1 gui=0 unify=0 select=diff" "echo x > core/osis/NotCargo.toml"
case_ "notes only" "core=docs gui=0 unify=0 select=none" "echo x >> notes/n.md"
case_ "spec, notes, issues" "core=docs gui=0 unify=0 select=none" "echo x >> spec/s.md; echo x >> notes/n.md; git rm -q issues/i.md"
case_ "notes and core" "core=1 gui=0 unify=0 select=diff" "echo x >> notes/n.md; echo x >> core/osis/a.rs"
case_ "notes and kit" "core=docs gui=1 unify=0 select=none" "echo x >> notes/n.md; echo x >> libs/kit/src/a.rs"
case_ "notes file moved to the root" "core=1 gui=0 unify=0 select=diff" "git mv notes/n.md n.md"
case_ "non-Markdown file under notes" "core=1 gui=0 unify=0 select=diff" "echo x > notes/v.txt"
case_ "non-ASCII Markdown name under spec" "core=docs gui=0 unify=0 select=none" "echo x > \"spec/\$(printf '\\303\\251').md\""
case_ "gate itself" "core=1 gui=0 unify=0 select=diff" "echo '#' >> tools/gate.sh"
case_ "kit and core" "core=1 gui=1 unify=0 select=diff" "echo x >> libs/kit/src/a.rs; echo x >> core/osis/a.rs"
case_ "core deleted" "core=1 gui=0 unify=0 select=diff" "git rm -q core/osis/a.rs"
case_ "kit, core and a manifest: not everything" "core=1 gui=1 unify=1 select=diff" "echo x >> libs/kit/src/a.rs; echo x >> Cargo.toml"
case_ "core moved into kit" "core=1 gui=1 unify=0 select=diff" "git mv core/osis/a.rs libs/kit/src/moved.rs"
case_ "engine file moved into app" "core=1 gui=1 unify=0 select=diff" "git mv core/engine/a.rs app/moved.rs"
check "--all" "core=1 gui=1 unify=1 select=all" --all
check "--base HEAD" "core=1 gui=1 unify=1 select=all" --base HEAD
check "--base bad" "exit 2: fatal: Needed a single revision" --base nonexistent
case_ "kit commit" "core=0 gui=1 unify=0 select=none" "echo x >> libs/kit/src/a.rs"
cd libs/kit/src  # not a subshell: check's counters must survive
check "from a subdirectory" "core=0 gui=1 unify=0 select=none"
cd ../../..
echo x > core/osis/new.rs
cd libs/kit/src
check "untracked core file, from a subdirectory" "core=1 gui=1 unify=0 select=diff"
cd ../../..
rm core/osis/new.rs
echo x >> core/osis/a.rs
check "uncommitted core edit" "core=1 gui=1 unify=0 select=diff"
git checkout -q core/osis/a.rs
echo x > core/osis/new.rs
check "untracked core file" "core=1 gui=1 unify=0 select=diff"
rm core/osis/new.rs
git checkout -q --detach
check "detached HEAD" "core=0 gui=1 unify=0 select=none"
git checkout -q t
# a source on main reading notes/: a notes-only branch then runs everything, naming it (last: main changes)
git checkout -q main; echo 'let _ = std::fs::read_to_string("../notes/n.md");' > core/osis/r.rs; git add -A; git commit -qm reader
case_ "notes only, a source reads notes" "gate: docs-only diff, but these read spec/, notes/ or issues/ (add them to the docs step): full gate
core/osis/r.rs:1:let _ = std::fs::read_to_string(\"../notes/n.md\");
core=1 gui=0 unify=0 select=diff" "echo x >> notes/n.md"
git checkout -q main; git checkout -qb fresh; echo x >> libs/kit/src/a.rs
check "uncommitted kit edit, no commits (base = HEAD)" "core=1 gui=1 unify=1 select=all"
git checkout -q libs/kit/src/a.rs
git checkout -q --orphan orph; git commit -qm orphan
check "no merge base" "core=1 gui=1 unify=1 select=all"
git checkout -q t; git branch -qm main old
check "no main branch" "core=1 gui=1 unify=1 select=all"
echo "gate selection: $n cases, $([ $fail = 0 ] && echo ok || echo FAILED)"
exit $fail
