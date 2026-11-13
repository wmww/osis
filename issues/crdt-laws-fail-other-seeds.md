# osis-crdt property tests fail at other seeds on main
> Summary: Three osis-crdt lib tests pass at the committed seeds but fail at most other `OSIS_CRDT_SEED`s on main: `tests_laws::entry_copies::forged_entry_copies_join_and_expire_alike_spec_5_6` ("expiry 0 before the joins": a text inside a forged map entry keeps a delete flag the other order drops), `tests_life::sweep_laws_spec_sync_7` ("the view's read"), `tests_seq_ops::small_joins_follow_cached_placement_spec_6`.
> Priority: normal
> Tags: crdt, tests

Reproduce on main: `OSIS_CRDT_SEED=2134411 cargo test -p osis-crdt --lib` (entry copies, sweep laws), `OSIS_CRDT_SEED=33` (small joins). Seen in nearly every seed tried (11, 22, 55, 99, 1234, 231666, 749955...). Each states a law, so each failure is a property that does not hold (notes/coordination.md, A failure rate is not a property): turn each into a minimal reproducer and fix, or find the generator bug.
