#!/bin/sh
# Tests tools/land against a temp repo with a bare origin and a stub tools/policy.py (exits
# $POLICY_RC): it pushes only from a clean tree containing origin/main whose policy passes.
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
printf 'import os, sys\nsys.exit(int(os.environ.get("POLICY_RC", "0")))\n' > tools/policy.py
git add -A && git commit -qm base && git push -q origin HEAD:main
tip() { git --git-dir="$d/origin.git" rev-parse main; }
base=$(tip)
echo x > f && git add f && git commit -qm one
POLICY_RC=1 "$land" 2> /dev/null && rc=0 || rc=$?
check "policy fails: refused" "$rc $(tip)" "1 $base"
echo y >> f
POLICY_RC=0 "$land" 2> /dev/null && rc=0 || rc=$?
check "dirty: refused" "$rc $(tip)" "1 $base"
git checkout -q f
# another landing moves origin/main: HEAD lacks it
git clone -q "$d/origin.git" "$d/b" 2> /dev/null
(cd "$d/b" && git config user.email t@t && git config user.name t && echo z > g && git add g && git commit -qm other && git push -q origin HEAD:main)
moved=$(tip)
POLICY_RC=0 "$land" 2> /dev/null && rc=0 || rc=$?
check "behind: refused" "$rc $(tip)" "1 $moved"
git rebase -q origin/main
POLICY_RC=0 "$land" 2> /dev/null && rc=0 || rc=$?
check "clean, current, policy ok: pushed" "$rc $(tip)" "0 $(git rev-parse HEAD)"
exit $fail
