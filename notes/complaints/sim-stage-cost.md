# sim-stage-cost
- `tools/cpuprof` symbolizes against the binary path after the run: rebuilding `target/debug/sim-sweep` during a profiled run gave a nonsense report. Profile a copy of the binary.
- `sim-sweep` reports no per-scenario CPU; measuring it took a throwaway probe (thread CPU from `/proc/thread-self/schedstat` per job) in the sweep binary.
- Two `tools/heavy` sweeps of about 2 min each waited 26 min and 10+ min for the lock (TLC and gate holds).
- Review: `sim-sweep` silences its panic hook, so a main-thread panic (an unknown `OSIS_*` env var refused by `testenv::check_known`) exits 101 with no message at all.
