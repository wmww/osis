# Bare sequence records depend on arrival order
> Summary: stripping a snapshot's copies leaves records with no write (`SeqElem { created: None, content: None, pos: [], deleted: None }`) in one order and none in another: reads alike, states and stored rows differ, and `Seq`'s equality says they differ.
> Tags: tests, crdt

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_seq_bare_records_order_spec_crdt_4_6` (order seed 1028: 1 puts a text entry, 2 writes in it and compacts, 0 lowers 2 to read; held without 1's commit).

`seq::drop_creations` leaves the records "as anchors", and `SeqElem::keeps` never drops a record. A bare record joins as nothing, so this is only a difference of state, but it keeps the states of two nodes unequal. The order harness compares states without them (`order::plain_state`); remove that with the fix. Likely fix: a record with no write and no element anchored at it goes, whichever path left it; check rule 3 of spec/crdt.md §5.7 and any anchor use first.
