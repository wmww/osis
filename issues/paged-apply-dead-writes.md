# Streamed and whole dead-write tallies differ (paged-apply differential)
> Summary: `apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8` fails about 40% of seeds (10 of 24 from 542710263009, 9 of 24 from 1, seed 1 and 807694656266 included, so the per-branch size fails too) on the debug cross-check in `retention::bounds::replaced_at`: `dead writes streamed vs whole`, the streamed `tally` counting more of a stamp than `oracle::dead_writes` (e.g. 4 against 1). Fails on e3cdd005f and 8f3cd8d05; the bounds code changed in the retention-3 reviews.
> Priority: normal
> Tags: engine, retention, tests

Replay (12 s): `OSIS_PAGED_APPLY_START=1 OSIS_PAGED_APPLY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8`.

The maps differ in a count per `(stamp, dot)` key, not in which writes are dead (seen: `(…7, STid(..)/58284d2a:2): (4, Ts(…13))` streamed against `(1, Ts(…13))` whole). Either the streamed `deaths` reports one death several times over pages (a write re-reported per page or per held copy), or the oracle undercounts. Which side is right decides whether `replaced_at` dates bodies wrongly (keep-for-D bounds). In the same default-range run seed 22 or 23 was reported hung (notes/test-design.md step 6).
