# tier1-trim
- No profiler on the box (no perf, gdb, lldb, py-spy): finding where a test's CPU went took writing an LD_PRELOAD SIGPROF sampler (now `tools/cpuprof`). Without it the guesses (final re-sync of the paged test, harness re-delivery) were partly wrong.
- Running a copied test binary directly (outside cargo) runs proptests at 256 cases, not the 32 `.cargo/config.toml` sets: my first per-test CPU table had the crdt `tests_seq` proptests at 22-27 CPU-s instead of about 4. Export `PROPTEST_CASES=32` in any harness that runs binaries itself.
- `/usr/bin/time` under `LD_PRELOAD` runs the preload too and its atexit overwrote the test's sample file: hence per-pid output files.
- Gate took 1095 s at load 40-53: the GUI workspace check alone 308 s (kit/target cold in this worktree).
- Review: `claudewait` with a mistyped task ID just errors (exit 2); harmless. Gate 442 s at load 31-41. The rotation `--ignored rotation::tests::` filter also runs the known-failing `holder_keyset_name_not_met_by_roster_snapshot_spec_crypto_4` (issues/keyset-names-start-escape.md): a reviewer must recognise that red line as expected.
