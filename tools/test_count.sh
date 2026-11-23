#!/bin/sh
# Cargo's runner for the gate's default-test stages (tools/test_watch.py sets it): names the test
# binary, `gate: binary CRATE/NAME` (NAME the file's name without cargo's hash), then runs it under
# tools/icount, whose `INSTR <n>` tools/gate_failures.py holds to tools/test_cost.txt (notes/gate.md,
# The summary: Test cost).
echo "gate: binary $CARGO_PKG_NAME/$(basename "$1" | sed 's/-[0-9a-f]*$//')" >&2
exec "$(dirname "$0")/icount" "$@"
