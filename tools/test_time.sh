#!/bin/sh
# Cargo's runner for the gate's default-test stages (tools/test_watch.py sets it): runs the test
# binary with libtest's per-test wall times, `test NAME ... ok <W.WWWs>` (notes/gate.md, Slow tests).
# RUSTC_BOOTSTRAP only in the binary's environment: through cargo it would build a second artifact set.
RUSTC_BOOTSTRAP=1 exec "$@" -Zunstable-options --report-time
