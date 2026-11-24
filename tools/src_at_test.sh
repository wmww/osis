#!/bin/sh
# Tests tools/src-at on a two-crate workspace in a temp dir: OUT runs the branch's test against the
# library's sources at REV (a module the branch added gone), the tree is the branch's again after,
# a dirty tree is refused, and a failing build leaves the sources swapped back. Exit 1 on a mismatch.
set -eu
src_at=$(cd "$(dirname "$0")" && pwd)/src-at
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
fail=0
check() { [ "$2" = "$3" ] || { echo "FAIL $1: got '$2', want '$3'"; fail=1; }; }
git init -q -b main "$d/repo"
cd "$d/repo"
git config user.email t@t && git config user.name t
mkdir -p lib/src user/tests
printf '[workspace]\nmembers = ["lib", "user"]\nresolver = "2"\n' > Cargo.toml
printf '[package]\nname = "lib"\nversion = "0.1.0"\nedition = "2021"\n' > lib/Cargo.toml
printf '[package]\nname = "user"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nlib = { path = "../lib" }\n' > user/Cargo.toml
: > user/src.rs
printf '[lib]\npath = "src.rs"\n' >> user/Cargo.toml
printf 'pub fn say() -> &%sstatic str { "old" }\n' "'" > lib/src/lib.rs
printf '#[test]\nfn says() { println!("{}", lib::say()); }\n' > user/tests/it.rs
printf 'target\n' > .gitignore
cargo generate-lockfile -q --offline 2> /dev/null || cargo generate-lockfile -q
git add -A && git commit -qm old
old=$(git rev-parse HEAD)
# the branch: a new module in the library, and a new test
printf 'mod extra;\npub fn say() -> &%sstatic str { extra::NEW }\n' "'" > lib/src/lib.rs
printf 'pub const NEW: &str = "new";\n' > lib/src/extra.rs
printf '#[test]\nfn says() { println!("{}", lib::say()); }\n#[test]\nfn added() {}\n' > user/tests/it.rs
git add -A && git commit -qm new
git worktree add -q -b task "$d/wt" HEAD
cd "$d/wt"
"$src_at" "$old" lib "$d/out/it" -p user 2> "$d/err" || { cat "$d/err"; exit 1; }
check "OUT: the branch's test" "$("$d/out/it" --list 2>&1 | grep -c ': test$')" 2
check "OUT: REV's library" "$("$d/out/it" --nocapture says 2>&1 | grep -c '^old$')" 1
check "back: branch, clean, its sources" "$(git symbolic-ref --short HEAD) $(git status --porcelain | wc -l) $(cat lib/src/extra.rs)" 'task 0 pub const NEW: &str = "new";'
echo edit >> user/tests/it.rs
"$src_at" "$old" lib "$d/out/it2" -p user 2> "$d/err" && rc=0 || rc=$?
check "dirty tree refused, edit kept" "$rc $(tail -1 user/tests/it.rs)" "1 edit"
git checkout -q -- user/tests/it.rs
# REV's sources do not build with the branch's tests: the failure leaves the branch's tree
printf 'pub fn other() {}\n' > lib/src/lib.rs && git commit -qam broken && broken=$(git rev-parse HEAD)
git reset -q --hard HEAD~1
"$src_at" "$broken" lib "$d/out/it3" -p user > /dev/null 2>&1 && rc=0 || rc=$?
check "failed build: refused, swapped back" "$rc $(git symbolic-ref --short HEAD) $(git status --porcelain | wc -l) $(head -1 lib/src/lib.rs)" "101 task 0 mod extra;"
"$src_at" "$old" nosuch "$d/out/x" -p user 2> /dev/null && rc=0 || rc=$?
check "unknown crate" "$rc" 2
exit $fail
