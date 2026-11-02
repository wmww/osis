# An inbox blob can block a group's label before the group is known
> Summary: `state.hints` holds one hint per label, first blob ID wins, and an open label stays under the hint's thing on the connection: a connected sender naming label L under a thing it boxes to you keeps you from L's own group until the blob expires (`INBOX_LIFETIME`).
> Tags: security, node-sync

An honest sender no longer does this (spec/wire.md §9: a thing names only its own label; `item_grant_then_group_grant_reaches_the_group_spec_wire_9` is that case). A sender can still write any label into a payload, and the recipient cannot judge it until it holds the `label.0` recording it (`vet_inbox_hints` skips a recorded label; before that it has only the sender's word).

Two pieces, both in `sync/inbound.rs` `vet_inbox_hints` and `sync/mod.rs` `add_new_labels`:
- Two blobs naming one label under different things: `want.get_mut` keeps the first by blob ID, so the genuine grant's hint never runs and its label.0 never arrives.
- `add_new_labels` treats any entry in `c.labels` as known: a label opened (or Failed) under a hint's thing stays so when `labels()` later names it under its group. Restarting needs care: a reply to an Open in flight would hit the new attempt's tries (`refused` drops the first try).

Needs: a hint per (label, thing), each tried in turn, or a `known` that compares the group and waits for no Open in flight. Cost of the attack: one admitted blob, one grant delayed; the sender must be connected and know the label.
