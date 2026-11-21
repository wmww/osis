# test-speed-3
- A seed loop's fixed seeds can miss a whole branch: `own_demotion_keyset_*` (seeds 0..4) never took its read-again branch, which fails on every seed that does (issues/own-demotion-read-rotated-again.md). Converting a loop to a `_plain` property, run it once at an offset (`OSIS_*_START=<n>`) before committing.
- `PageParams::set_test` is thread-local: a test moved onto `Seeds::run` (seed threads) must set it inside the per-seed closure, or the seeds run at default page sizes and pass for the wrong reason.
- Whole-binary counts under `tools/heavy` waited 4-5 min for the lock each time; per-module `tools/icount` without the lock answered the piece-1 question in seconds.
