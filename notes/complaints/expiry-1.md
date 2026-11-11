# expiry-1
- `tests_seq_ops::text_batch_over_history_spec_4_5` passed only because write-less text records kept a text slot beside a register: a text op on a register-only position failed ("range out of range"); `ops::present_slot` now reads the register's embedding there (spec/crdt.md §7).
- `snapshot_edits_follow_cache_spec_6` had a split coverage floor (`split >= 25` over 12 fixed seeds) that depended on write-less range records; it needed more seeds once they went.
- Review: `fuzz_seq::random_scripts_replay_spec_5_7` names no failing script index, so `OSIS_SHRINK=<n>` needs a loop over 0..32 to find it; it should print the index (and the shrink command) on failure.
