#!/bin/sh
# Tests tools/claim against a temp repo with a bare origin and a fake `wt` (claim: a git worktree
# of BRANCH, made from BASE when new; list: path and branch): a new branch starts at origin/main, a
# stale local branch is reset to its pushed copy (naming the refs still holding what it dropped), an ancestor fast-forwards, a dirty worktree moves
# nothing, a leftover bisect is ended, the known-failures merge driver is set, and the fuzz target loses
# its release profiles, or everything when its build key changed. Exit 1 on a mismatch.
set -eu
claim=$(cd "$(dirname "$0")" && pwd)/claim
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
fail=0
check() { [ "$2" = "$3" ] || { echo "FAIL $1: got '$2', want '$3'"; fail=1; }; }
mkdir "$d/bin"
cat > "$d/bin/wt" <<'EOF'
#!/bin/sh
set -e
top=$(git rev-parse --show-toplevel)
case $1 in
claim)
    n=$(ls "$top/.wts" 2> /dev/null | wc -l); p="$top/.wts/w$n"
    if git rev-parse -q --verify "refs/heads/$2" > /dev/null; then git worktree add -q "$p" "$2"; else git worktree add -q -b "$2" "$p" "$3"; fi
    [ -z "${FAKE_DIRTY:-}" ] || echo x > "$p/junk"
    [ -z "${FAKE_BISECT:-}" ] || git -C "$p" bisect start -q HEAD HEAD~1 > /dev/null
    echo "$2" > "$top/.wtclaim$n"; echo "$p" ;;
list) for c in "$top"/.wtclaim*; do n=${c##*.wtclaim}; echo "$top/.wts/w$n $(cat "$c") (claimed)"; done ;;
esac
EOF
chmod +x "$d/bin/wt"
PATH="$d/bin:$PATH"
git init -q --bare -b main "$d/origin.git"
git clone -q "$d/origin.git" "$d/a" 2> /dev/null
cd "$d/a"
git config user.email t@t && git config user.name t
echo base > f && git add f && git commit -qm base && git push -q origin HEAD:main
# a worker's branch pushed as coord-task, then rebased and pushed again: the local copy is stale
git checkout -qb task && echo one > g && git add g && git commit -qm one
git push -q origin task:coord-task
git checkout -q main && echo two >> f && git commit -qam two && git push -q origin HEAD:main
git checkout -q task && git rebase -q main && git push -q -f origin task:coord-task
git reset -q --hard HEAD~1 && echo old > g && git add g && git commit -qm "pre-rebase one"
git checkout -q main
git branch other task
w=$("$claim" task 2> "$d/err")
check "stale local reset to the pushed copy" "$(git -C "$w" rev-parse HEAD)" "$(git rev-parse origin/coord-task)"
check "dropped commits named where kept" "$(grep -c 'each is still on other' "$d/err")" "1"
check "merge driver set" "$(git config merge.known-failures.driver)" "python3 tools/known_failures_merge.py %O %A %B"
# a new branch starts at origin/main as fetched
w2=$("$claim" fresh 2> /dev/null)
check "new branch at origin/main" "$(git -C "$w2" rev-parse HEAD)" "$(git rev-parse origin/main)"
# an ancestor of the pushed copy fast-forwards; a dirty worktree moves nothing
git branch behind origin/main~1
git push -q origin "$(git rev-parse origin/main)":refs/heads/coord-behind
w3=$("$claim" behind 2> /dev/null)
check "ancestor fast-forwarded" "$(git -C "$w3" rev-parse HEAD)" "$(git rev-parse origin/coord-behind)"
git branch dirty origin/main~1
git push -q origin "$(git rev-parse origin/main)":refs/heads/coord-dirty
FAKE_DIRTY=1 "$claim" dirty > /dev/null 2>&1 && rc=0 || rc=$?
check "dirty: refused, nothing moved" "$rc $(git -C "$d/a/.wts/w3" rev-parse HEAD)" "1 $(git rev-parse origin/main~1)"
# an earlier task's bisect left in the worktree is ended
w5=$(FAKE_BISECT=1 "$claim" bisected 2> /dev/null)
check "bisect ended" "$(git -C "$w5" bisect log > /dev/null 2>&1 && echo bisecting || echo none) $(git -C "$w5" rev-parse HEAD)" "none $(git rev-parse origin/main)"
# the fuzz target: stamped when first seen; release profiles dropped; emptied on a new build key
mkdir -p core/test/fuzz && echo lock1 > core/test/fuzz/Cargo.lock && echo target/ > core/test/fuzz/.gitignore
git add core && git commit -qm fuzz && git push -q origin HEAD:main
w6=$("$claim" fuzzed 2> /dev/null)
t=$w6/core/test/fuzz/target
check "fuzz target stamped" "$(ls -A "$t")" ".claim-key"
mkdir -p "$t/release/build" "$t/x86_64-unknown-linux-gnu/release" "$t/x86_64-unknown-linux-gnu/debug" "$t/debug"
fuzz() { python3 -c 'import importlib.machinery as m, sys; m.SourceFileLoader("claim", sys.argv[1]).load_module().fuzz_target(sys.argv[2])' "$claim" "$w6" 2> /dev/null; }
fuzz
check "release profiles dropped" "$(cd "$t" && find . -mindepth 1 | sort | tr '\n' ' ')" "./.claim-key ./debug ./x86_64-unknown-linux-gnu ./x86_64-unknown-linux-gnu/debug "
echo lock2 > "$w6/core/test/fuzz/Cargo.lock"
fuzz
check "new key: emptied" "$(ls -A "$t")" ".claim-key"
check "no branch: usage" "$("$claim" > /dev/null 2>&1 && echo 0 || echo $?)" "1"
exit $fail
