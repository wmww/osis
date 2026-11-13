# An osis-crdt property test fails at another seed
> Summary: `tests_seq_ops::small_joins_follow_cached_placement_spec_6` passes at its committed seed but fails at `OSIS_CRDT_SEED=33` (`follow` work at 300 runs over 4x that at 30). It states a law, so the failure is a property that does not hold: reduce it to a minimal reproducer and fix, or find the generator bug.
> Priority: normal
> Tags: crdt, tests

Reproduce: `OSIS_CRDT_SEED=33 cargo test -p osis-crdt --lib small_joins_follow_cached_placement` (under a second). The entry-copies law failing at other seeds is issues/forged-entry-copies-expiry-seed.md.
