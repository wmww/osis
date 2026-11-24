# review-purge
- A coverage floor tuned to the old rule (`expiring_snapshots_read_alike_*`: 3 expiring snapshots dropped as covered over 10 fixed seeds) failed only at the gate: the branch's own runs never ran that property. A rule change that narrows what covers what should rerun the properties counting that path before review.
- `tools/gate_failures.py` prints the cost table first; the NEW lines are under `== test stages` far below, and the panic text only in the gate log: grep the log for `panicked at` to read it.
- `grep -o '/[^ ]*deps/props-...'` on cargo's `Executable` line drops the path prefix (it prints `(target/...)`): use `ls -t target/debug/deps/<name>-*` for icount.
- An engine lib build behind a gate's heavy hold took about 8 minutes; batch mutation runs per build.
