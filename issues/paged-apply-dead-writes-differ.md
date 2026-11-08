# Paged-apply differential: dead-write counts differ, streamed vs whole
> Summary: `apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8` fails at seed 1 (plain size, 2 seeds) on main: `retention::bounds` `tally` counts a stamp's dead writes 4 where `oracle::dead_writes` counts 1. Not looked into.
> Priority: normal
> Tags: tests, engine, retention

Replay: `OSIS_PAGED_APPLY_START=1 OSIS_PAGED_APPLY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8`. Fails with the tree at f0f831bbd too. The differing entry is one stamp of a session's second counter (`left` 4, `right` 1); the rest of the map agrees.
