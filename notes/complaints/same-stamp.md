# same-stamp
- Order/walks oracles print their seed-range summary only with `--nocapture`; a passing run under plain `cargo test` shows just `1 passed`, so confirming the range took a second run.
- Debugging a failing osis-crdt proptest: the `Debug` dump of two states is one huge line; diffing needed a throwaway script. A test helper printing the first differing record would save time.
- Review: `OSIS_CRDT_SEED=973451` fails `tests_seq::derived_dots_follow_cache_spec_7` on main too (derived follows 2 < 20): its "fixed seeds" go through `testutil::rng`, so the env seed shifts them and the count threshold is seed-sensitive. `--include-ignored` also runs ignored known-failing repros (`forged_creation_ts_undelete_char`), so that periodic command always shows failures to sift.
