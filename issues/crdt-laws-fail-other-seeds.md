# osis-crdt property tests fail at other seeds on main
> Summary: `tests_seq_ops::small_joins_follow_cached_placement_spec_6` (seed 33) and `tests_seq::slots_join_follows_cache_spec_7` (seed 5) pass at the committed seeds but fail at other `OSIS_CRDT_SEED`s on main. Each states a law, so each failure is a property that does not hold: turn it into a minimal reproducer and fix, or find the generator bug.
> Priority: normal
> Tags: crdt, tests

Reproduce: `OSIS_CRDT_SEED=33 cargo test -p osis-crdt --lib small_joins_follow_cached_placement`, `OSIS_CRDT_SEED=5 cargo test -p osis-crdt --lib slots_join_follows_cache`. The entry-copies law failing at other seeds (seed 2134411) is its own issue: issues/forged-entry-copies-expiry-seed.md.
