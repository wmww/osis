# eph-churn-demote
- `OSIS_EPH_TRACE=<commit prefix>` misses arrivals (a blob not opened yet has commit `-`): trace by the blob prefix to see where a waiting entry came from.
- The churn oracle's step log and the trace are separate streams, so the order of lane events against steps (restarts, promotions) has to be guessed.
- Two seeds in 140000..140300 hang (on main too); the seed runner then kills the whole run at 600 s and no other seed's result is printed: a 300-seed run cost 11 min and told nothing until rerun around them.
- 3 of the 10 seeds in the brief were a different class (expired non-value writes), not the demotion one; diagnosing that took a temporary state dump in the engine.
- Review: no debugger or profiler on the box (no gdb, perf); finding where a hung seed spins took a ptrace stack-scanning script, then a temporary SIGUSR1 handler printing `Backtrace::force_capture()` (needs the workspace `unsafe_code = "forbid"` lowered for the probe build). A test-harness hook that dumps the seed thread's backtrace on the seed timeout would have answered it in one run.
