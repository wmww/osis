# Forged entry copies: expiry before the joins keeps a Derived text record
> Summary: `tests_laws::entry_copies::forged_entry_copies_join_and_expire_alike_spec_5_6` fails on main at `OSIS_CRDT_SEED` 917311, 4402113, 77310519 and 2854516606: stripping expiry 0 (everything) per copy before joining leaves a `Derived` text record (flag-only delete, no creation) that stripping after the join drops, so expiry does not commute with join.
> Priority: normal
> Tags: crdt, tests

Reproduce: `OSIS_CRDT_SEED=2854516606 cargo test -p osis-crdt --lib -- forged_entry_copies` (effective seed 13791819631566251439, committed 157; at 917311: committed 15). The `early` state holds `D(<B>:5):1` in the `Text` slot with only `deleted: (…C:17, true)`; `late` lacks it. Next: a hand-written reproducer (two copies, one strip), then decide which side's strip is wrong (spec/crdt.md §4.7, §5.7 Element existence).
