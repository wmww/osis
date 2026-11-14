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
# origin: the gate's base is the merge base with origin/main (fetched), never local main
git init -q --bare -b main ../up.git; git remote add origin ../up.git; git push -q origin main
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
# the comments path (the classifier's own cases: tools/gate_paths_test.py)
case_ "core comment" "core=comments gui=0 unify=0 select=none" "echo '// x' >> core/osis/a.rs"
case_ "core comment mid-file" "core=comments gui=0 unify=0 select=none" "sed -i '3i // b' core/osis/a.rs"
case_ "trailing comment" "core=1 gui=0 unify=0 select=diff" "sed -i 's|^5\$|5 // x|' core/osis/a.rs"
case_ "comment line in a string" "core=1 gui=0 unify=0 select=diff" "printf '\"\\n// s\\n\"\\n' >> core/osis/a.rs"
case_ "comments, notes and kit" "core=comments gui=1 unify=0 select=none" "echo '// x' >> core/osis/a.rs; echo x >> notes/n.md; echo x >> libs/kit/src/a.rs"
case_ "new comment-only file" "core=1 gui=0 unify=0 select=diff" "echo '// x' > core/osis/c.rs"
case_ "comment and a manifest" "core=1 gui=0 unify=1 select=diff" "echo '// x' >> core/osis/a.rs; echo x >> Cargo.toml"
case_ "doc comment, no cargo metadata" "core=1 gui=0 unify=0 select=diff" "echo '/// x' >> core/osis/a.rs"
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
echo '// x' >> core/osis/a.rs
check "uncommitted core comment" "core=comments gui=1 unify=0 select=none"
git checkout -q core/osis/a.rs
echo x > core/osis/new.rs
check "untracked core file" "core=1 gui=1 unify=0 select=diff"
rm core/osis/new.rs
git checkout -q --detach
check "detached HEAD" "core=0 gui=1 unify=0 select=none"
git checkout -q t
# a source on main reading notes/: a notes-only branch then runs everything, naming it (last: main changes)
git checkout -q main; echo 'let _ = std::fs::read_to_string("../notes/n.md");' > core/osis/r.rs; git add -A; git commit -qm reader; git push -q origin main
case_ "notes only, a source reads notes" "gate: docs or comments diff, but these read spec/, notes/ or issues/ (add them to the docs step): full gate
core/osis/r.rs:1:let _ = std::fs::read_to_string(\"../notes/n.md\");
core=1 gui=0 unify=0 select=diff" "echo x >> notes/n.md"
git checkout -q main; git checkout -qb fresh; echo x >> libs/kit/src/a.rs
check "uncommitted kit edit, no commits (base = HEAD)" "core=1 gui=1 unify=1 select=all"
git checkout -q libs/kit/src/a.rs
git checkout -q --orphan orph; git commit -qm orphan
check "no merge base" "core=1 gui=1 unify=1 select=all"
# local main behind origin/main (pushed from another checkout): origin's work is not the branch's
git checkout -q main; echo x >> core/osis/a.rs; git commit -qam "merged elsewhere"; git push -q origin main; git reset -q --hard HEAD^
git checkout -q -b lag origin/main; echo x >> libs/kit/src/a.rs; git commit -qam lag
check "local main behind origin/main" "core=0 gui=1 unify=0 select=none"
check "--base local main" "core=1 gui=1 unify=0 select=diff" --base main
# --plan fetches: a push from elsewhere reaches origin/main; a failed fetch warns and keeps the last one
git clone -q ../up.git ../other; (cd ../other && git -c user.email=t@t -c user.name=t commit -q --allow-empty -m elsewhere && git push -q origin main)
check "fetches origin/main" "core=0 gui=1 unify=0 select=none"
n=$((n + 1)); [ "$(git rev-parse origin/main)" = "$(git -C ../up.git rev-parse main)" ] || { echo "FAIL --plan did not fetch origin/main"; fail=1; }
git remote set-url origin ../missing.git
check "fetch fails" "gate: fetching origin main failed; using the last fetched one
core=0 gui=1 unify=0 select=none"
git checkout -q t; git remote remove origin
check "no origin/main" "core=1 gui=1 unify=1 select=all"
# the hold's runner (--held): only under tools/heavy (HEAVY_HELD), each `run LIMIT CMD` line in order with
# stdin closed, every one run, `LIMIT EXIT LOG` per run in runs.res; exit 1 if any failed; `build` lines are not its
held() {
  name=$1 want=$2; shift 2
  rm -f ran; rc=0; got=$(env "$@" sh "$gate" --held runs 2>&1) || rc=$?
  got="exit $rc: $(printf '%s\n' "$got" | grep -v -e '^   (' -e '^   limit ' | tr '\n' '|')ran: $(cat ran 2>/dev/null | tr '\n' ' ')res: $(cut -d' ' -f1,2 runs.res 2>/dev/null | tr '\n' ' ')"
  n=$((n + 1)); if [ "$got" = "$want" ]; then :; else echo "FAIL held $name: got '$got', want '$want'"; fail=1; fi
}
printf '%s\n' "build echo b >> ran" "run t echo 1 >> ran" "run t cat; echo 2 >> ran" "run t echo 3 >> ran" > runs
held "unlocked" "exit 2: gate: --held is internal: only the gate's tools/heavy hold runs it|ran: res: " -u HEAVY_HELD
held "every run, stdin closed" "exit 0: == sh -c echo 1 >> ran|== sh -c cat; echo 2 >> ran|== sh -c echo 3 >> ran|ran: 1 2 3 res: t 0 t 0 t 0 " HEAVY_HELD=1
printf '%s\n' "run a echo 1 >> ran" "run b echo out; exit 7" "run c echo 3 >> ran" > runs
held "a failure ends nothing" "exit 1: == sh -c echo 1 >> ran|== sh -c echo out; exit 7|out|== sh -c echo 3 >> ran|ran: 1 3 res: a 0 b 7 c 0 " HEAVY_HELD=1
[ "$(cat runs.2.log)" = out ] || { echo "FAIL held: runs.2.log is '$(cat runs.2.log)', want 'out'"; fail=1; }
# a default-tests stage whose target hangs (a fake cargo: target a's "binary" sleeps after
# libtest's 60-second notice): stopped after GATE_HANG_S, its running test named, target b still run
mkdir fakebin
cat > fakebin/cargo <<'FAKE'
#!/bin/sh
printf '     Running tests/a.rs (a-1)\n\nrunning 2 tests\ntest a::fine ... ok\n'
sh -c 'echo $$ > hung.pid; echo "test a::spin has been running for over 60 seconds"; exec sleep 300'
printf 'error: test failed, to rerun pass `--test a`\n     Running tests/b.rs (b-2)\n\nrunning 1 test\ntest b::fine ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\nerror: 1 target failed:\n    `--test a`\n'
exit 101
FAKE
chmod +x fakebin/cargo
echo "run default-tests cargo test --no-fail-fast" > runs
s0=$(date +%s); rc=0; env HEAVY_HELD=1 GATE_HANG_S=1 PATH="$PWD/fakebin:$PATH" sh "$gate" --held runs > /dev/null 2>&1 || rc=$?
took=$(( $(date +%s) - s0 ))
got="exit $rc, res $(cut -d' ' -f1,2 runs.res), hung $(grep -c '^gate: hung test: a::spin$' runs.1.log), b ran $(grep -c '^test b::fine \.\.\. ok$' runs.1.log)"
n=$((n + 1)); [ "$got" = "exit 1, res default-tests 101, hung 1, b ran 1" ] || { echo "FAIL held hang: got '$got'"; fail=1; }
n=$((n + 1)); [ "$took" -lt 60 ] || { echo "FAIL held hang: took ${took}s"; fail=1; }
n=$((n + 1)); ! kill -0 "$(cat hung.pid)" 2>/dev/null || { echo "FAIL held hang: the hung process $(cat hung.pid) still runs"; fail=1; kill "$(cat hung.pid)"; }
n=$((n + 1)); [ "$(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import gate_failures; print([x[0] for x in gate_failures.cargo_failures(open("runs.1.log").read())])' "$(dirname "$gate")")" = "['a::spin']" ] || { echo "FAIL held hang: the summary does not name a::spin"; fail=1; }
# a one-thread target (`test NAME ... ` printed at its start) whose cargo dies, its test orphaned
# holding the output pipe: the watcher (their subreaper) still stops it and names the test
cat > fakebin/cargo <<'FAKE'
#!/bin/sh
printf '     Running tests/a.rs (a-1)\n\nrunning 1 test\ntest a::spin ... '
sh -c 'echo $$ > hung.pid; exec sleep 300' &
while [ ! -s hung.pid ]; do :; done
kill -9 $$
FAKE
rm -f hung.pid
rc=0; out=$(env GATE_HANG_S=1 PATH="$PWD/fakebin:$PATH" python3 "$(dirname "$gate")/test_watch.py" cargo test 2>&1) || rc=$?
n=$((n + 1)); [ "$rc $(printf '%s\n' "$out" | grep -c -e '^gate: hung test: a::spin$' -e '^gate: hung: stopped [0-9].*, 1 processes$')" = "137 2" ] || { echo "FAIL orphan hang: rc $rc, out '$out'"; fail=1; }
n=$((n + 1)); ! kill -0 "$(cat hung.pid)" 2>/dev/null || { echo "FAIL orphan hang: $(cat hung.pid) still runs"; fail=1; kill "$(cat hung.pid)"; }
rm -rf runs runs.* ran fakebin hung.pid
echo "gate selection: $n cases, $([ $fail = 0 ] && echo ok || echo FAILED)"
exit $fail
