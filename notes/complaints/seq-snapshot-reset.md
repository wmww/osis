# seq-snapshot-reset review
> Summary: footguns met reviewing the prune-stable fix.

- A failing proptest run writes `proptest-regressions/*.txt`; replaying a found seed on an older commit with `git checkout <rev> -- core/crdt/src` keeps that file, so it replays there too (useful), but must be reverted before committing.
- `PROPTEST_CASES=500` on the decoder differentials found a pre-existing disagreement (a write copied across records of one map dot) in seconds that the 32-case tier 1 never hits: when touching a differential's rule, a reviewer run at a few hundred cases is cheap (about 25 s).
- Gate took 11 min wall at load 25-30 (548 s for the test step).
