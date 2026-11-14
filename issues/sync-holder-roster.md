# A sync holder sees the box keys of its grant's commit
> Summary: An inbox blob to a holder of sync alone carries the role commit's whole `secrets.0` part and header, so the holder learns the tids of every holder that commit boxes (a rotation: the roster of the rotated roles) and of every thing the commit touches; spec/sync-ids.md §2 states it as a limit. Fix: a payload of the recipient's own boxes.
> Priority: normal
> Tags: sync, engine, security

Spec/sync-ids.md §2 promises a holder of sync alone learns of the thing only its tid, never its roster. The sender (`core/engine/src/sync/deliveries.rs` `inbox_blob_with`) projects the commit to its `secrets.0` parts for such a recipient, but a projection keeps:
- the `secrets.0` delta whole: its box keys are (holder tid, role, epoch) for every box the commit writes; a rotation boxes every current holder of the rotated roles, so each sync rotation shows a sync holder the roster (and, by who is missing, who was removed);
- the header: author, `ts`, and `[tid, ak]` of every aspect the commit touches (the thing's other aspects; any other thing the commit carries).

The commit cannot be cut further: the part must hash to the header's, and the header must be whole for the author's signature (`sender_connected`).

Fix (a wire change, spec/wire.md §9): to a recipient holding sync alone, an inbox payload of its own boxes instead of the commit: `[tid, sync_id, [[role, epoch, box]+], author, Opt(epoch_id), sig]`, `sig` by the author under a new domain over the recipient, tid and boxes. The receiver opens each box with the AD it rebuilds (actor tid, holder, role, epoch, form), as `boxed_to` does from the delta now; taking by a connected sender checks `sig` instead of the commit signature; `held` (the commit already held) becomes the sync ID being in the sync set. Touches `osis_label` (payload, vectors, fuzz target), `deliveries.rs`, `sync/inbox.rs`, spec/wire.md §9, spec/sync-inbox.md §2, spec/crypto.md §2; then drop the limit from spec/sync-ids.md §2. Test: the sync-alone grant and rotation of `facade::a_sync_holder_is_sent_its_boxes_only_spec_sync_inbox_2` carry no other holder's tid.
