# slow-tests
- An old test binary (`tools/bin-at`, or a copy of the base build) reads the worktree's `core/base/testenv-known.txt` at run time: after removing a variable it still reads (`OSIS_ORDER_THREADS`), the base binary panics until the name is put back for the run.
- A/B runs of the order properties (base and branch, two offsets, each alone) held the heavy lock 713 s / 6136 CPU-s, over the `heavy` limit (1.2x): each exhaustive run is about 1100 CPU-s.
- A backgrounded `&` inside a Bash call outlives the call: a probe left running an exhaustive run outside the lock until stopped by PID.
- `tools/limits.py tests` now finds 5 tests over the `test` limit (the brief's list of 32 was stale: most were fixed by setup caching since).
