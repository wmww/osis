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
