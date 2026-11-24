#!/bin/sh
# Tests tools/merge-branch against a temp repo with a bare origin, the real tools/claim and
# tools/land, and fakes: wt (claim, list, release), tools/policy.py (exits $POLICY_RC),
# tools/gate.sh (prints a summary, exits $GATE_RC) and cargo (logs its arguments, exits $CARGO_RC).
# gate: a conflict in notes/handoff.md alone takes main's side, any other stops before the gate as
# does a policy failure; the gate's exit, log and summary come back. land: lands, deletes the pushed
# copy, releases the worktree and deletes the branch; refuses after a failed gate unless --fixed or
# its kept summary, read again against main's known failures, passes; when
# main moved, rebases and runs clippy and the tests of the packages both sides changed only, a failure
# stopping the landing. Exit 1 on a mismatch.
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
printf 'import os, sys\nsys.exit(int(os.environ.get("POLICY_RC", "0")))\n' > tools/policy.py
# GATE_KEEP=DIR: a failed gate keeps its files for the summary's re-read
printf '%s\n' 'echo "== test stages: 1 run of 1, 0 failed"' 'echo "== gate exit ${GATE_RC:-0}"' \
    'if [ -n "${GATE_KEEP:-}" ]; then mkdir -p "$GATE_KEEP" && touch "$GATE_KEEP/sel" "$GATE_KEEP/sel.res"' \
    '  echo "== summary again (kept): python3 tools/gate_failures.py $GATE_KEEP/sel $GATE_KEEP/sel.res"; fi' \
    'exit "${GATE_RC:-0}"' > tools/gate.sh
# the summary: KNOWN only (exit 3) when ROOT's known list names probe/x, else NEW (exit 1)
printf 'import sys\nsys.exit(3 if "probe/x " in open(sys.argv[3] + "/tools/known_failures.txt").read() else 1)\n' > tools/gate_failures.py
printf '[workspace]\nmembers = ["core/*"]\ndefault-members = ["core/*"]\n' > Cargo.toml
for p in x y; do printf '[package]\nname = "%s"\n' $p > core/$p/Cargo.toml; printf '1\n2\n3\n4\n5\n' > core/$p/f; done
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

# land after main moved: rebased, clippy and the tests of the package both sides changed (x, not y)
branch t4 core/x/f core/y/f
"$mb" gate t4 > /dev/null 2>&1
main core/x/f
"$mb" land t4 > /dev/null 2> "$d/err" && rc=0 || rc=$?
check "moved: landed" "$rc $(git --git-dir="$d/origin.git" log --format=%s -1 main)" "0 t4"
check "moved: checks of x only" "$(cat "$CARGO_LOG")" "clippy --all-targets -- -D warnings
test -p x"
rm "$CARGO_LOG"
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
exit $fail
