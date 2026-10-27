# A roster snapshot's late part leaves the incremental timeline stale
> Summary: A roster snapshot delivered with its `/members` part only, then its `/tenures` part late, gives the right index, reads and from-scratch timelines, but the incremental timeline lacks the late part's tenures: perm's `Timelines::append` fast path checks a thing's snapshots by ID only, and `join_late` replaces the snapshot under the same ID.
> Tags: perm, node

Found by the order harness's late-part delivery (osis-node `tests/it/order.rs` `deliver_split`) on found history seed 1173 (`arrival_order_found_histories_spec_crdt_4_6`): only the `timelines` section differs (`timelines from scratch` agrees). The harness skips splitting roster snapshots until fixed; drop that exclusion in `deliver_split` to reproduce.

Fix direction: `append` (osis-perm `incremental.rs`) must decline when a snapshot's content changed under its ID (compare the `Arc`s, or a generation per snapshot), or node `join_late` must make the replaced snapshot look new to perm.
