#!/bin/sh
# Tests tools/logrun: CMD's exit comes back, its output goes to LOG, the verdict lines print. Exit 1 on a mismatch.
tools=$(cd "$(dirname "$0")" && pwd)
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
out=$("$tools/logrun" "$d/sub/log" sh -c 'echo noise; echo "test result: FAILED. 1 passed; 1 failed"; exit 101')
rc=$?
[ "$rc" = 101 ] || { echo "FAIL exit: $rc"; exit 1; }
[ "$(grep -c noise "$d/sub/log")" = 1 ] || { echo "FAIL log"; exit 1; }
[ "$out" = "test result: FAILED. 1 passed; 1 failed
logrun: exit 101 ($d/sub/log)" ] || { echo "FAIL output: $out"; exit 1; }
# a filtered `cargo test` that ran nothing, or an `--exact` name that ran nowhere, exits 1
zero='echo "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out"'
"$tools/logrun" "$d/z" sh -c "$zero" test -- --skip x a::b > "$d/out"; rc=$?
[ "$rc" = 1 ] && grep -q "ran no test" "$d/out" || { echo "FAIL zero: $rc"; cat "$d/out"; exit 1; }
one='echo "test a::b ... ok"; echo "test result: ok. 1 passed; 0 failed"; echo "test result: ok. 0 passed; 0 failed"'
"$tools/logrun" "$d/e" sh -c "$one" test -- --exact a::b a::c > "$d/out"; rc=$?
[ "$rc" = 1 ] && grep -q -- "--exact a::c ran in no binary" "$d/out" && ! grep -q "a::b ran" "$d/out" || { echo "FAIL exact: $rc"; cat "$d/out"; exit 1; }
"$tools/logrun" "$d/f" sh -c "$one" test -- --exact a::b > "$d/out" || { echo "FAIL exact all ran"; cat "$d/out"; exit 1; }
"$tools/logrun" "$d/g" sh -c "$zero" build > "$d/out" || { echo "FAIL no filter"; exit 1; }
echo "logrun_test: ok"
