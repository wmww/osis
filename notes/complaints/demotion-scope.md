# demotion-scope
> Summary: Mishaps on the demotion-scope branch.

- A probe commit stamped with `now_ts` (wall, logical 0) landed before the node's own held commits of the same millisecond (test clocks are frozen, HLC logical counters climb), so the probe demoted nothing; only an engine rotation test caught it. A commit-to-be needs the HLC's next `ts` (`Hlc::peek`).
- `bench_demotion_scope` timings at load 25-30 vary 3x between runs; numbers in notes are ranges.
- Review: after narrowing two `pub(crate)` fns in osis-perm to private (and a `cargo clippy -p osis-perm`), every `--test it` binary failed to link (`undefined hidden symbol: osis_perm::walk::drive (.llvm.…)`): stale incremental codegen units. `cargo clean -p osis-perm` fixed it (4.1 GB removed, 71 s rebuild).
- Review: a fix-disabled probe that only emptied the loop's answer still passed (the `all_held` start already lists the aspects); the probe had to empty the scope the frontier is built from.
