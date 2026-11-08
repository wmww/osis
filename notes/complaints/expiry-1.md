# expiry-1
- `tests_seq_ops::text_batch_over_history_spec_4_5` passed only because write-less text records kept a text slot beside a register: a text op on a register-only position failed ("range out of range"); `ops::present_slot` now reads the register's embedding there (spec/crdt.md §7).
- `range_splits_follow_cache_spec_6` had a coverage floor (`split >= 25` over 12 fixed seeds) that depended on write-less range records; it needed more seeds once they went.
