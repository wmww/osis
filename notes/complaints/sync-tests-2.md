# sync-tests-2
> Summary: Footguns and slow spots met cutting osis-sync default tests (second pass).

- Per-test `--exact` icount numbers mislead badly for osis-sync: most tests on `world(0, 4)` read 30-40 G each while their in-binary marginal is 2-10 G (the fixture is built once per process). Judge by module and whole-binary counts, and subtract the fixture before ranking tests.
- A memo's `try_settle` returns `None` for an unchanged answer, so a probe counting `was == Some(now)` after it reads zero: count `Some` returns (moved) against total runs instead.
- The fixture-sharing levers here were small (whole binary 864 -> 861 G): the remaining cost is the product's per-delivery judging, not test setup.
