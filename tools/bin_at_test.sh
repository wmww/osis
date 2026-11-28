#!/bin/sh
# Tests tools/bin-at on a one-crate repo in a temp dir: OUT runs REV's code, the branch is checked
# out again, and target/ keeps no REV binary at cargo's path (running it later ran old code); several
# targets in one call land in OUT/CRATE/.
# Exit 1 on a mismatch.
set -eu
bin_at=$(cd "$(dirname "$0")" && pwd)/bin-at
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
fail=0
check() { [ "$2" = "$3" ] || { echo "FAIL $1: got '$2', want '$3'"; fail=1; }; }
git init -q -b main "$d/repo"
cd "$d/repo"
git config user.email t@t && git config user.name t
mkdir -p src tests
printf '[package]\nname = "probe"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n' > Cargo.toml
: > src/lib.rs
mkdir -p src/bin
printf 'fn main() { println!("old"); }\n' > src/bin/say.rs
printf 'target\n' > .gitignore
printf '#[test]\nfn says() { println!("old"); }\n' > tests/it.rs
git add -A && git commit -qm old
old=$(git rev-parse HEAD)
printf '#[test]\nfn says() { println!("new"); }\n' > tests/it.rs
printf 'fn main() { println!("new"); }\n' > src/bin/say.rs
git commit -qam new
git worktree add -q -b task "$d/wt" HEAD
cd "$d/wt"
"$bin_at" "$old" "$d/out/it" -p probe 2> "$d/err" || { cat "$d/err"; exit 1; }
check "OUT runs REV" "$("$d/out/it" --nocapture says 2>&1 | grep -c '^old$')" 1
check "branch back" "$(git symbolic-ref --short HEAD)" task
check "no REV binary left in target" "$(find target/debug/deps -maxdepth 1 -type f -name 'it-*' -perm -u+x | wc -l)" 0
cargo test -q --no-run 2> /dev/null
exe=$(find target/debug/deps -maxdepth 1 -type f -name 'it-*' -perm -u+x)
check "the next build is the branch's" "$("$exe" --nocapture says 2>&1 | grep -c '^new$')" 1
"$bin_at" "$old" "$d/out/say" -p probe --bin say 2> "$d/err" || { cat "$d/err"; exit 1; }
check "--bin: OUT runs REV's binary" "$("$d/out/say")" old
check "--bin: branch back" "$(git symbolic-ref --short HEAD)" task
"$bin_at" "$old" "$d/many/" -p probe -p probe --bin say --lib probe 2> "$d/err" || { cat "$d/err"; exit 1; }
check "several: the test" "$("$d/many/probe/test-it" --nocapture says 2>&1 | grep -c '^old$')" 1
check "several: the binary" "$("$d/many/probe/bin-say")" old
check "several: the lib" "$("$d/many/probe/lib" --list 2>&1 | grep -c 'tests, 0 benchmarks')" 1
check "several: no REV binary left in target" "$(find target/debug/deps -maxdepth 1 -type f -name 'it-*' -perm -u+x | wc -l)" 0
rc=0; "$bin_at" "$old" "$d/two" -p probe --lib probe 2> /dev/null || rc=$?
check "several into a file: refused" "$rc" 2
check "refused: branch back" "$(git symbolic-ref --short HEAD)" task
exit $fail
