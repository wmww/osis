# big-map-rewrite
- The issue pointed at engine paging (`ensure_paths`, `OP_RUNS`); the quadratic was in osis-crdt `diff` (a scan of every stored key per new key). A cpuprof or icount at n and 4n first would have found it in minutes.
- No in-process work counter for CPU-bound steps (unsafe is forbidden, so no perf_event_open in tests): a scaling test of an algorithmic step needs a hand-placed `cfg(test)` probe.
