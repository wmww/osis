#!/bin/sh
# Tests core/test/tla/run.sh on a copy in a temp dir with a fake java (TLC's result per cfg from
# $TLC_RESULTS, `cfg=pass|fail|error` words): a negative control that passes, or an error, fails the
# run yet every later instance and the summary still run; the expected results exit 0. Exit 1 on a
# mismatch.
set -eu
tla=$(cd "$(dirname "$0")/../core/test/tla" && pwd)
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
fail=0
check() { [ "$2" = "$3" ] || { echo "FAIL $1: got '$2', want '$3'"; fail=1; }; }
mkdir -p "$d/bin" "$d/core/test/tla/rotation"
cp "$tla/run.sh" "$d/core/test/tla/"
: > "$d/jar"
cat > "$d/bin/java" <<'J'
#!/bin/sh
while [ $# -gt 0 ]; do [ "$1" = -config ] && cfg=$2; shift; done
r=pass
for w in $TLC_RESULTS; do [ "${w%%=*}" = "$cfg" ] && r=${w#*=}; done
case $r in
pass) echo "Model checking completed. No error has been found." ;;
fail) echo "Error: Invariant Safe is violated." ;;
*) echo "Error: parse" ;;
esac
echo "12 distinct states found"
J
chmod +x "$d/bin/java"
PATH="$d/bin:$PATH"
export TLA_JAR="$d/jar"
run=$d/core/test/tla/run.sh
# RS_newest, RS_forged: listed fail (negative controls); RS_closed: listed pass
cfgs="RS_newest RS_forged RS_closed"

TLC_RESULTS="RS_newest.cfg=fail RS_forged.cfg=fail" bash "$run" reseal $cfgs > "$d/out" 2>&1 && rc=0 || rc=$?
check "expected results: exit" "$rc" 0
check "expected results: every instance and the summary" "$(grep -c ' ok$' "$d/out") $(grep -c '^reseal: ' "$d/out")" "3 1"

TLC_RESULTS="RS_forged.cfg=fail" bash "$run" reseal $cfgs > "$d/out" 2>&1 && rc=0 || rc=$?
check "control passes: exit" "$rc" 1
check "control passes: verdicts" "$(grep -oE '^RS_[a-z]+\.cfg +[a-z]+ .* (ok|FAILED)$' "$d/out" | awk '{ print $1, $2, $NF }' | tr '\n' ';')" \
    "RS_newest.cfg pass FAILED;RS_forged.cfg fail ok;RS_closed.cfg pass ok;"
check "control passes: summary" "$(grep -c '^reseal: ' "$d/out")" 1

TLC_RESULTS="RS_newest.cfg=error RS_forged.cfg=fail" bash "$run" reseal $cfgs > "$d/out" 2>&1 && rc=0 || rc=$?
check "error: exit, later instances, summary" "$rc $(grep -c ' ok$' "$d/out") $(grep -c '^reseal: ' "$d/out")" "1 2 1"
exit $fail
