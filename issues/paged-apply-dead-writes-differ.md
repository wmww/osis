# Paged-apply differential: dead-write counts differ, streamed vs whole
> Summary: `apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8` fails on main at seeds 1 and 807694656266 (each one of the 2 a plain run takes): `retention::bounds` `tally` counts a stamp's dead writes 4 where `oracle::dead_writes` counts 1. Not looked into.
> Priority: normal
> Tags: tests, engine, retention

Replay: `OSIS_PAGED_APPLY_START=1 OSIS_PAGED_APPLY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8` (or `_START=807694656266`). Both fail with main's tree at b2623eda5. The differing entry is one stamp of a session's second counter (`left` 4, `right` 1); the rest of the map agrees. Failing half the seeds of a plain run, the oracle tells nothing per branch until fixed.
