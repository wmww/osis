# tier1-trim
- No profiler on the box (no perf, gdb, lldb, py-spy): finding where a test's CPU went took writing an LD_PRELOAD SIGPROF sampler (now `tools/cpuprof`). Without it the guesses (final re-sync of the paged test, harness re-delivery) were partly wrong.
- Running a copied test binary directly (outside cargo) runs proptests at 256 cases, not the 32 `.cargo/config.toml` sets: my first per-test CPU table had the crdt `tests_seq` proptests at 22-27 CPU-s instead of about 4. Export `PROPTEST_CASES=32` in any harness that runs binaries itself.
- `/usr/bin/time` under `LD_PRELOAD` runs the preload too and its atexit overwrote the test's sample file: hence per-pid output files.
- Gate took 1095 s at load 40-53: the GUI workspace check alone 308 s (kit/target cold in this worktree).
