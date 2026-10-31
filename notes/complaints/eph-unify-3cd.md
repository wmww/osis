# eph-unify-3cd
- The brief's (c)+(d) scope hid four step-4/5 design questions (coalescing, covers, presence drop, node cap over Core); found only after reading remote.rs and the lane. A design pass before briefing the swap would have saved the worker most of the reading.
- `durable_on(..).next()` looks O(1) but scans every memory commit on the aspect: the bench caught a 2x regression that tier 1 never would. Re-run `bench_local_writes` under `tools/icount` at two sizes after touching the commit path.
