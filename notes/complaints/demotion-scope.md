# demotion-scope
> Summary: Mishaps on the demotion-scope branch.

- A probe commit stamped with `now_ts` (wall, logical 0) landed before the node's own held commits of the same millisecond (test clocks are frozen, HLC logical counters climb), so the probe demoted nothing; only an engine rotation test caught it. A commit-to-be needs the HLC's next `ts` (`Hlc::peek`).
- `bench_demotion_scope` timings at load 25-30 vary 3x between runs; numbers in notes are ranges.
