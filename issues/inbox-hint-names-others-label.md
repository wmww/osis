# An inbox blob can delay a group's label before the group is known
> Summary: `state.hints` holds one hint per label, first blob ID wins: a connected sender naming label L under a thing it boxes to you keeps you from L's own group until the blob expires (`INBOX_LIFETIME`).
> Tags: security, node-sync

An honest sender no longer does this (spec/wire.md §9: a thing names only its own label; `item_grant_then_group_grant_reaches_the_group_spec_wire_9` is that case). A sender can still write any label into a payload, and the recipient cannot judge it until it holds the `label.0` recording it (`vet_inbox_hints` skips a recorded label; before that it has only the sender's word).

In `sync/inbound.rs` `vet_inbox_hints`: two blobs naming one label under different things: `want.get_mut` keeps the first by blob ID, so the genuine grant's hint never runs and its label.0 never arrives. A label left Failed under the hint's thing gives way once `wanted_labels` names it under another (`add_new_labels`; `hint_under_another_thing_gives_way_to_the_group_spec_sync_3`).

Needs: a hint per (label, thing), each tried in turn. Cost of the attack: one admitted blob, one grant delayed; the sender must be connected and know the label.
