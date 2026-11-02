# A snapshot of a sequence with fallen writes: reads depend on arrival order
> Summary: with a text writer demoted and a valid snapshot of the aspect held, one order reads the fallen writer's chars and another does not (`x` vs `v2x`), the same in nested texts (`v7v1` vs `v7v1v1`), and an in-place un-merge can differ from a rebuild (a debug assertion). A violation of spec/requirements.md Decentralization in user-visible reads, on honest histories.
> Tags: security, tests, crdt, engine, permissions

Repros (all fail): `cargo test -p osis-node --test it -- --ignored repro_seq_snapshot_`.
- `repro_seq_snapshot_unmerge_read_order_spec_crdt_4_6` (order seed 1007): 1 and 2 write `t:text.0`, 0 demotes 2 with a frontier missing 2's write, 2's commit reaches 0, 0 compacts. As made reads `x`, reversed reads `v2x`.
- `repro_seq_snapshot_nested_read_order_spec_crdt_4_6` (seed 1018): the same for texts in map entries; the extra `v1` is the fallen 2's own insert, carried by 0's snapshot.
- `repro_seq_snapshot_unmerge_in_place_spec_crdt_4_6` (seed 1045): `unmerged_as_rebuilt` panics on `t:docs.0` while a peer plays the history.

The order harness never reached these: its untyped writes could not write a sequence at all. Generated histories leave out compactions of `t:text.0` and `t:docs.0` until this is fixed (`order::skip_seq_snapshot_unmerge`, also used for a `Nested` text's compaction; lists still compact, and `order::arrival_order_seq_compact_large_*` compacts them with nothing fallen); remove that skip with the fix. Then pin the histories in `order::arrival_order_found_histories_*`.

What differs in the first two: the fallen write's records are alike, creation and all; only the char differs. 0's snapshot, written from a state where the insert is a hidden anchor, carries its creation with no char. As made, the un-merge has already taken the char and the snapshot adds none (the right read: spec/crdt.md §4.6, a content-less hidden anchor). Snapshot before the invalid delta, the char joins and the un-merge keeps it, the creation being a write a valid snapshot carries (§4.1: a text char goes with its creation's stamp). A valid snapshot's copy with no char must not vouch for the char. Start at `apply::atomic::unmerge_part` and `Fragment::strip_copies`/`seq::drop_creations`, `seq::remove_dots`.

Not triaged, may be this family or its own: order seed 709033 (`OSIS_ORDER_SEED=709033 cargo test -p osis-node --test it order::arrival_order_alike_large -- --ignored`): `t:list.0` has no aspect row as made and a row reading absent in another order, with a list compaction in the history (lists are not skipped). It fails the large oracle; no skip.
