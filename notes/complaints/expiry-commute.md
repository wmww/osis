# expiry-commute
- The differential has no shrinker: a temporary probe test (drop deltas while the assertion still fails, print the rest) took a 48-write hostile history to 3 deltas in one run. Worth a standing helper beside `check_case`.
- A test binary run outside cargo (icount, cpuprof) without `PROPTEST_CASES=32 PROPTEST_DISABLE_FAILURE_PERSISTENCE=1` counts 170 G for osis-crdt instead of 48 G: the footgun is documented, but a `tools/icount` that set cargo's `[env]` itself would remove it.
- osis-crdt sits at its test_cost line (48.0 G of 48); `tests_winners::winners_from_scratch_spec_4_8` is 8.9 G of it, mostly `incremental_check` re-dating every step.
