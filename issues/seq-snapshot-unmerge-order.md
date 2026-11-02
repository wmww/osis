# A snapshot of a sequence with fallen writes: reads depend on arrival order
> Summary: with a text writer demoted and a valid snapshot of the aspect held, one order reads the fallen writer's chars and another does not (`x` vs `v2x`), nested texts read chars twice (`v7v1` vs `v7v1v1`), and an in-place un-merge can differ from a rebuild (a debug assertion). A violation of spec/requirements.md Decentralization in user-visible reads, on honest histories.
> Tags: tests, crdt, engine, permissions

Repros (all fail): `cargo test -p osis-node --test it -- --ignored repro_seq_snapshot_`.
- `repro_seq_snapshot_unmerge_read_order_spec_crdt_4_6` (order seed 1007): 1 and 2 write `t:text.0`, 0 demotes 2 with a frontier missing 2's write, 2's commit reaches 0, 0 compacts. As made reads `x`, reversed reads `v2x`.
- `repro_seq_snapshot_nested_chars_twice_spec_crdt_4_6` (seed 1018): the same for texts in map entries.
- `repro_seq_snapshot_unmerge_in_place_spec_crdt_4_6` (seed 1045): `unmerged_as_rebuilt` panics on `t:docs.0` while a peer plays the history.

The order harness never reached these: its untyped writes could not write a sequence at all. Generated histories leave out compactions of `t:text.0` and `t:docs.0` until this is fixed (`order::skip_seq_snapshot_unmerge`; lists still compact); remove that skip with the fix. Then pin the histories in `order::arrival_order_found_histories_*`.

Not diagnosed further. Start at `apply::atomic::unmerge_part` and `Fragment::strip_copies`/`seq::drop_creations`: an invalid insert stays as a hidden anchor (`seq::remove_dots`), and a snapshot's copy of it has no char to give.
