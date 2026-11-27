#!/bin/sh
# Tests tools/land against a temp repo with a bare origin and a stub tools/policy.py (runs
# $POLICY_HOOK, exits $POLICY_RC): it pushes only from a clean tree containing origin/main whose policy passes; refused
# behind origin/main (also when it moved while policy ran), it names the files both sides changed; `--delete BRANCH` deletes only after a push.
# Exit 1 on a mismatch.
set -eu
land=$(cd "$(dirname "$0")" && pwd)/land
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
fail=0
check() { [ "$2" = "$3" ] || { echo "FAIL $1: got '$2', want '$3'"; fail=1; }; }
git init -q --bare -b main "$d/origin.git"
git clone -q "$d/origin.git" "$d/a" 2> /dev/null
cd "$d/a"
git config user.email t@t && git config user.name t
mkdir tools
printf 'import os, subprocess, sys\nif os.environ.get("POLICY_HOOK"): subprocess.run(os.environ["POLICY_HOOK"], shell=True, check=True)\nsys.exit(int(os.environ.get("POLICY_RC", "0")))\n' > tools/policy.py
printf '1\n2\n3\n4\n5\n' > c
git add -A && git commit -qm base && git push -q origin HEAD:main
tip() { git --git-dir="$d/origin.git" rev-parse main; }
base=$(tip)
echo x > f && sed -i 1s/1/one/ c && git add f c && git commit -qm one
POLICY_RC=1 "$land" 2> /dev/null && rc=0 || rc=$?
check "policy fails: refused" "$rc $(tip)" "1 $base"
echo y >> f
POLICY_RC=0 "$land" 2> /dev/null && rc=0 || rc=$?
check "dirty: refused" "$rc $(tip)" "1 $base"
git checkout -q f
# another landing moves origin/main: HEAD lacks it
git clone -q "$d/origin.git" "$d/b" 2> /dev/null
(cd "$d/b" && git config user.email t@t && git config user.name t && echo z > g && sed -i 5s/5/five/ c && git add g c && git commit -qm other && git push -q origin HEAD:main)
moved=$(tip)
POLICY_RC=0 "$land" 2> "$d/err" && rc=0 || rc=$?
check "behind: refused" "$rc $(tip)" "1 $moved"
check "behind: names the file both sides changed" "$(grep -c '(c )' "$d/err")" "1"
git push -q origin HEAD:refs/heads/coord-x
POLICY_RC=0 "$land" --delete coord-x 2> /dev/null && rc=0 || rc=$?
check "behind, --delete: branch kept" "$rc $(git ls-remote "$d/origin.git" coord-x | wc -l)" "1 1"
git rebase -q origin/main
# another landing while policy runs: refused at the second fetch
POLICY_HOOK="cd $d/b && echo w > h && git add h && git commit -qm during && git push -q origin HEAD:main" "$land" 2> "$d/err" && rc=0 || rc=$?
check "moved during policy: refused" "$rc $(grep -c 'landed while policy ran' "$d/err")" "1 1"
git fetch -q origin && git rebase -q origin/main
POLICY_RC=0 "$land" --delete coord-x 2> /dev/null && rc=0 || rc=$?
check "clean, current, policy ok: pushed" "$rc $(tip)" "0 $(git rev-parse HEAD)"
check "pushed, --delete: branch deleted" "$(git ls-remote "$d/origin.git" coord-x | wc -l)" "0"
"$land" --delete main 2> /dev/null && rc=0 || rc=$?
check "--delete main: refused" "$rc" "1"
exit $fail
