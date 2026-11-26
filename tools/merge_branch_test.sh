#!/bin/sh
# Tests tools/merge-branch against a temp repo with a bare origin, the real tools/claim and
# tools/land, and fakes: wt (claim, list, release), tools/policy.py (exits $POLICY_RC),
# tools/gate.sh (prints a summary, exits $GATE_RC) and cargo (logs its arguments, exits $CARGO_RC).
# gate: a conflict in notes/handoff.md alone takes main's side, any other stops before the gate as
# does a policy failure; the gate's exit, log and summary come back. land: lands, deletes the pushed
# copy, releases the worktree and deletes the branch; refuses after a failed gate unless --fixed or
# its kept summary, read again against main's known failures and cost lines, passes; when
# main moved, rebases and runs clippy and the tests of the packages both sides changed only (again
# while main moves during them), a failure stopping the landing; the summary's KNOWN-BUT-PASSED and STALE-COST lines are applied in a commit
# landed with it (STALE-RATE too). Exit 1 on a mismatch.
set -eu
tools=$(cd "$(dirname "$0")" && pwd)
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
fail=0
check() { [ "$2" = "$3" ] || { echo "FAIL $1: got '$2', want '$3'"; fail=1; }; }
mkdir "$d/bin"
cat > "$d/bin/wt" <<'EOF'
#!/bin/sh
set -e
top=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")
case $1 in
claim)
    n=$(ls "$top/.wts" 2> /dev/null | wc -l); p="$top/.wts/w$n"
    if git rev-parse -q --verify "refs/heads/$2" > /dev/null; then git worktree add -q "$p" "$2"; else git worktree add -q -b "$2" "$p" "$3"; fi
    echo "$2" > "$top/.wtclaim$n"; echo "$p" ;;
list) for c in "$top"/.wtclaim*; do [ -e "$c" ] || continue; n=${c##*.wtclaim}; echo "$top/.wts/w$n $(cat "$c") (claimed)"; done ;;
release) git -C "$2" checkout -q --detach; rm "$top/.wtclaim${2##*/w}" ;;
esac
EOF
cat > "$d/bin/cargo" <<'EOF'
#!/bin/sh
echo "$*" >> "$CARGO_LOG"
# CARGO_HOOK: a command run at the first call (main moving during a land's checks)
if [ -n "${CARGO_HOOK:-}" ] && [ ! -e "$CARGO_LOG.hooked" ]; then touch "$CARGO_LOG.hooked"; sh -c "$CARGO_HOOK" > /dev/null 2>&1; fi
exit "${CARGO_RC:-0}"
EOF
chmod +x "$d/bin/wt" "$d/bin/cargo"
PATH="$d/bin:$PATH"
export CARGO_LOG="$d/cargo.log"
git init -q --bare -b main "$d/origin.git"
git clone -q "$d/origin.git" "$d/a" 2> /dev/null
cd "$d/a"
# every push below goes to the temp bare remote only: stop if this is any other repo
[ "$(git remote get-url origin)" = "$d/origin.git" ] && [ "$(git rev-parse --show-toplevel)" = "$d/a" ] || { echo "FAIL: not the temp repo"; exit 1; }
git config user.email t@t && git config user.name t
mkdir -p tools notes core/x core/y
cp "$tools/merge-branch" "$tools/claim" "$tools/land" "$tools/known_failures_merge.py" tools/
# POLICY_HOOK: a command run at the first call (main moving between tools/land's fetch and its push)
printf '%s\n' 'import os, subprocess, sys' 'h, m = os.environ.get("POLICY_HOOK"), os.environ.get("CARGO_LOG", "") + ".policy-hooked"' \
    'if h and not os.path.exists(m): open(m, "w").close(); subprocess.run(["sh", "-c", h], capture_output=True)' \
    'sys.exit(int(os.environ.get("POLICY_RC", "0")))' > tools/policy.py
# GATE_KEEP=DIR: a failed gate keeps its files for the summary's re-read
# GATE_STALE: summary lines to print (KNOWN-BUT-PASSED, STALE-COST)
printf '%s\n' 'echo "== test stages: 1 run of 1, 0 failed"' 'printf "%b" "${GATE_STALE:-}"' 'echo "== gate exit ${GATE_RC:-0}"' \
    'if [ -n "${GATE_KEEP:-}" ]; then mkdir -p "$GATE_KEEP" && touch "$GATE_KEEP/sel" "$GATE_KEEP/sel.res"' \
    '  echo "== summary again (kept): python3 tools/gate_failures.py $GATE_KEEP/sel $GATE_KEEP/sel.res"; fi' \
    'exit "${GATE_RC:-0}"' > tools/gate.sh
# the summary: KNOWN only (exit 3) when ROOT's known list names probe/x and its cost list holds
# probe/b at 2 or more (or not at all), else NEW (exit 1)
printf '%s\n' 'import re, sys' 'r = sys.argv[3] + "/tools/"' 'b = re.findall(r"^probe/b (\S+)$", open(r + "test_cost.txt").read(), re.M)' \
    'sys.exit(3 if "probe/x " in open(r + "known_failures.txt").read() and all(float(g) >= 2 for g in b) else 1)' > tools/gate_failures.py
printf '[workspace]\nmembers = ["core/*"]\ndefault-members = ["core/*"]\n' > Cargo.toml
for p in x y; do printf '[package]\nname = "%s"\n' $p > core/$p/Cargo.toml; printf '1\n2\n3\n4\n5\n' > core/$p/f; cp core/$p/f core/$p/g; done
echo base > notes/handoff.md
git add -A && git commit -qm base && git push -q origin HEAD:main
mb="$d/a/tools/merge-branch"
tip() { git --git-dir="$d/origin.git" rev-parse main; }
# a branch BRANCH changing FILES (line 1 of each), pushed as coord-BRANCH
branch() { b=$1; shift; git checkout -q -b "$b" origin/main; for f in "$@"; do sed -i "1s/.*/$b/" "$f"; done; git commit -qam "$b"; git push -q origin "$b:coord-$b"; git checkout -q --detach origin/main; }
# main changing FILES (line 5 of each, or the whole of notes/handoff.md)
main() { git checkout -q --detach origin/main; for f in "$@"; do sed -i "5s/.*/main$(git rev-list --count HEAD)/;1s/^base$/main/" "$f"; done; git commit -qam main; git push -q origin HEAD:main; git fetch -q; }
git checkout -q --detach

# gate: the handoff conflicts alone and takes main's side; the gate's exit, summary and log come back
branch t1 core/x/f notes/handoff.md
main notes/handoff.md
"$mb" gate t1 > "$d/out" 2> "$d/err" && rc=0 || rc=$?
w=$(git worktree list | awk '$3 == "[t1]" { print $1 }')
check "gate: exit" "$rc" "0"
check "gate: handoff is main's" "$(cat "$w/notes/handoff.md")" "main"
check "gate: on origin/main" "$(git -C "$w" merge-base --is-ancestor origin/main HEAD && echo yes)" "yes"
check "gate: summary printed" "$(grep -c '^== gate exit 0' "$d/out")" "1"
check "gate: log recorded" "$(tail -1 .git/gate-logs/t1/gate-1.log)" "gate=0"
check "gate: log path printed" "$(grep -c "^log: $d/a/.git/gate-logs/t1/gate-1.log" "$d/out")" "1"
# land, main unmoved: pushed, pushed copy deleted, released, branch and logs gone
head=$(git -C "$w" rev-parse HEAD)
"$mb" land t1 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "land: exit, main" "$rc $(tip)" "0 $head"
check "land: pushed copy deleted" "$(git ls-remote "$d/origin.git" coord-t1 | wc -l)" "0"
check "land: released, branch deleted, logs gone" "$(ls .wtclaim* 2> /dev/null | wc -l) $(git branch --list t1 | wc -l) $(ls .git/gate-logs)" "0 0 "
check "land: no cargo run" "$(cat "$CARGO_LOG" 2> /dev/null | wc -l)" "0"
git fetch -q

# gate: policy failing stops before the gate; another conflict stops with its files
branch t2 core/x/f
POLICY_RC=1 "$mb" gate t2 > /dev/null 2>&1 && rc=0 || rc=$?
check "policy fails: refused, no gate log" "$rc $(ls .git/gate-logs/t2 2> /dev/null | grep -c log || true)" "2 0"
branch t3 core/y/f
git checkout -q --detach origin/main && sed -i 1s/.*/other/ core/y/f && git commit -qam other && git push -q origin HEAD:main && git fetch -q
"$mb" gate t3 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "other conflict: refused, files named" "$rc $(grep -c 'conflicts in: core/y/f' "$d/err")" "2 1"
check "other conflict: no gate log" "$(ls .git/gate-logs/t3 2> /dev/null | grep -c log || true)" "0"

# land after a failed gate: refused; --fixed lands
branch t5 core/x/f
GATE_RC=1 "$mb" gate t5 > /dev/null 2>&1 && rc=0 || rc=$?
before=$(tip)
"$mb" land t5 > /dev/null 2>&1 && rc=0 || rc=$?
check "failed gate: land refused" "$rc $(tip)" "1 $before"
"$mb" land t5 --fixed > /dev/null 2>&1 && rc=0 || rc=$?
check "failed gate, --fixed: landed" "$rc $(git branch --list t5 | wc -l)" "0 0"
git fetch -q

# land after a failed gate whose NEW failure main listed since: its summary read again lands it
branch t7 core/x/f
GATE_RC=1 GATE_KEEP="$d/keep7" "$mb" gate t7 > /dev/null 2>&1 && rc=0 || rc=$?
before=$(tip)
"$mb" land t7 > /dev/null 2>&1 && rc=0 || rc=$?
check "failed gate, main unlisted: land refused" "$rc $(tip)" "1 $before"
git checkout -q --detach origin/main && mkdir -p issues && echo i > issues/p.md
echo "probe/x rate:1 issues/p.md fails" > tools/known_failures.txt
git add issues/p.md tools/known_failures.txt && git commit -qm listed && git push -q origin HEAD:main && git fetch -q
"$mb" land t7 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "failed gate, listed on main since: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -1 main)" "0 t7"
check "failed gate, listed: re-read said" "$(grep -c 'read again against origin/main.s known failures exits 3' "$d/err")" "1"
rm -f "$CARGO_LOG"
git fetch -q

# land after a failed gate whose NEW-COST main raised since: the re-read takes main's cost line
git checkout -q --detach origin/main && printf 'probe/a 5\nprobe/b 1\n' > tools/test_cost.txt
git add tools/test_cost.txt && git commit -qm costs && git push -q origin HEAD:main && git fetch -q
branch t8 core/x/f
GATE_RC=1 GATE_KEEP="$d/keep8" "$mb" gate t8 > /dev/null 2>&1 && rc=0 || rc=$?
before=$(tip)
"$mb" land t8 > /dev/null 2>&1 && rc=0 || rc=$?
check "failed gate, cost unraised: land refused" "$rc $(tip)" "1 $before"
git checkout -q --detach origin/main && printf 'probe/a 5\nprobe/b 3\n' > tools/test_cost.txt
git commit -qam raised && git push -q origin HEAD:main && git fetch -q
"$mb" land t8 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "failed gate, cost raised on main since: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -1 main)" "0 t8"
rm -f "$CARGO_LOG"
git fetch -q

# land after main moved: rebased, clippy and the tests of the package both sides changed (x, not
# y), each side in another file of it
branch t4 core/x/f core/y/f
"$mb" gate t4 > /dev/null 2>&1
main core/x/g
"$mb" land t4 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "moved: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -1 main)" "0 t4"
check "moved: checks of x only" "$(cat "$CARGO_LOG")" "clippy --all-targets -- -D warnings
test -p x"
rm "$CARGO_LOG"
git fetch -q

# main moves again during the land's checks: rebased again, and the second round checks only what
# main changed since the first (y)
git clone -q "$d/origin.git" "$d/c" 2> /dev/null
git -C "$d/c" config user.email t@t && git -C "$d/c" config user.name t
branch t5 core/x/f core/y/f
"$mb" gate t5 > /dev/null 2>&1
main core/x/g
CARGO_HOOK="cd $d/c && git pull -q && sed -i 5s/.*/moved/ core/y/g && git commit -qam moved && git push -q origin HEAD:main" \
    "$mb" land t5 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "moved during checks: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -2 main | tr "\n" " ")" "0 t5 moved "
check "moved during checks: x, then y" "$(grep '^test' "$CARGO_LOG" | tr "\n" " ")" "test -p x test -p y "
rm -f "$CARGO_LOG" "$CARGO_LOG.hooked"
git fetch -q

# main moves after the land's last check, before tools/land pushes (its push refused): rebased and
# checked again, then landed
branch t10 core/x/f core/y/f
"$mb" gate t10 > /dev/null 2>&1
POLICY_HOOK="cd $d/c && git pull -q && sed -i 5s/.*/late/ core/y/g && git commit -qam late && git push -q origin HEAD:main" \
    "$mb" land t10 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "moved before the push: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -2 main | tr "\n" " ")" "0 t10 late "
check "moved before the push: y checked" "$(grep '^test' "$CARGO_LOG" | tr "\n" " ")" "test -p y "
rm -f "$CARGO_LOG" "$CARGO_LOG.policy-hooked"
git fetch -q

# a failing check after the land's rebase stops it; the rerun needs --fixed
branch t6 core/x/f
"$mb" gate t6 > /dev/null 2>&1
main core/x/f
before=$(tip)
CARGO_RC=1 "$mb" land t6 > /dev/null 2>&1 && rc=0 || rc=$?
check "check fails: not landed" "$rc $(tip)" "1 $before"
"$mb" land t6 > /dev/null 2>&1 && rc=0 || rc=$?
check "check failed: land refused" "$rc $(tip)" "1 $before"
"$mb" land t6 --fixed > /dev/null 2>&1 && rc=0 || rc=$?
check "check failed, --fixed: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -1 main)" "0 t6"
rm -f "$CARGO_LOG"
git fetch -q

# the land's rebase stops on a conflict; finished by hand, the next land checks and lands it
branch t8 core/y/f core/x/f
"$mb" gate t8 > /dev/null 2>&1
w=$(git worktree list | awk '$3 == "[t8]" { print $1 }')
# a commit after the checked HEAD (a fix) rides along
echo fix > "$w/core/x/g" && git -C "$w" add core/x/g && git -C "$w" commit -qm fix8
git checkout -q --detach origin/main && sed -i 1s/.*/other8/ core/y/f && git commit -qam other8 && git push -q origin HEAD:main && git fetch -q
"$mb" land t8 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "land conflict: stopped, files named" "$rc $(grep -c 'conflicts in: core/y/f' "$d/err")" "1 1"
git -C "$w" checkout -q --theirs core/y/f && git -C "$w" add core/y/f && git -C "$w" -c core.editor=true rebase --continue > /dev/null 2>&1
"$mb" land t8 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "land conflict finished by hand: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -2 main | tr "\n" " ")" "0 fix8 t8 "
check "land conflict finished by hand: checks ran" "$(grep -c 'clippy --all-targets' "$CARGO_LOG")" "1"

# a passing gate's KNOWN-BUT-PASSED, STALE-RATE and STALE-COST lines: applied in a commit landed with
# the branch; a `rate:` line not replayed passing, and a cost line main changed since the gate, kept
git checkout -q --detach origin/main
printf 'probe/x rate:1 issues/p.md fails\nprobe/m::k - issues/p.md fails\nprobe/m::k rate:1 issues/p.md other\nsim-sweep:s 3 issues/p.md fails\n' > tools/known_failures.txt
printf 'probe/a 5\nprobe/b 3\nprobe/c 8\nprobe/d 9\nprobe/gone 4\n' > tools/test_cost.txt
git commit -qam lists && git push -q origin HEAD:main && git fetch -q
branch t9 core/x/f
GATE_STALE='   KNOWN-BUT-PASSED: m::k (default-tests; issues/p.md)\n   STALE-RATE: probe/x rate:1 (its REPRO passed; issues/p.md)\n   KNOWN-BUT-PASSED: sim-sweep:s (gate.sim; issues/p.md)\n   STALE-COST: probe/c (default-tests; 1 G instructions, under its line 8 / 2: lower it to 1.5)\n   STALE-COST: probe/d (default-tests; 1 G instructions, under its line 9 / 2: lower it to 1.5)\n   STALE-COST: probe/gone (its crate ran, it did not: drop the line)\n' "$mb" gate t9 > /dev/null 2>&1
git checkout -q --detach origin/main && sed -i 's/^probe\/d 9$/probe\/d 20/' tools/test_cost.txt && git commit -qam raised-d && git push -q origin HEAD:main && git fetch -q
"$mb" land t9 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "stale lines: landed with their commit" "$rc $(git --git-dir="$d/origin.git" log --format=%s -2 main | tr "\n" " ")" "0 land: the gate's stale known-failure and test-cost lines t9 "
check "stale lines: known list" "$(git --git-dir="$d/origin.git" show main:tools/known_failures.txt)" "probe/m::k rate:1 issues/p.md other"
check "stale lines: cost list" "$(git --git-dir="$d/origin.git" show main:tools/test_cost.txt)" "probe/a 5
probe/b 3
probe/c 1.5
probe/d 20"
exit $fail
