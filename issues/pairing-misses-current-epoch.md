# A node paired after a device removal can miss a current epoch
> Summary: sync `flows::a_node_pairs_another_after_removing_its_pairer_spec_sync_inbox_1` fails whenever commit bytes shift (a field added to `retention_setting`; earlier, moving a link K's record): the new node holds an epoch 2 of some thing but not the one its sibling holds current, so two epochs numbered 2 exist and which one the new node is given depends on commit-ID order. A real key-passing bug the test reaches by luck of IDs; not root-caused.
> Priority: normal
> Tags: keys, sync

- Seen: `Tid(..) Sync 2 lacks its secret at the new node`; the sibling's current sync epochs are `[2]`, the new node's `[2]` too, a different nonce. The thing is none of D, the profile, the inbox or the node root (a card link K or the devices actor are the likely ones).
- Fails with the history-holds code disabled, so the trigger is the setting's encoding alone (every struct field is encoded, so every `retention^.0` delta grew by one field), which moves commit IDs.
- Wanted: a constructed reproducer (two rotations of one thing at epoch 2, the pairing reading the other), then the fix; the test above stays as it is.
