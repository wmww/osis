# Established epochs: what node-core, node-sync and membership-flows must implement
> Summary: spec/crypto.md §4 "established" is the one notion behind current epochs, history boxes, re-seal and registration. osis-keys implements it (notes/crypto.md, osis-keys bullet); these are the obligations of its callers.
> Tags: keys, crypto, permissions, sync

## node-core
- Done (notes/node.md, Established epochs): `applied`, `snapshot_keyed`, `unset_applied`, persistence, compaction gate, headers kept.
- Retention: before dropping a body with live writes (keep-at-most bound, at most 0, timed) a writer writes a covering snapshot when it holds none (spec/commits.md §5); the deletion queue entry for a timed delete carries "snapshot first".
- Carrier tiebreaks of spec/sync.md §7 (identical body: higher blob ID goes; covered-equal snapshots: higher commit ID goes).

## node-sync
- Done (notes/sync.md, Implementation (osis-node sync)): per (server, label) pass completion and `SyncEngine::complete_pass(actor)`; re-registration order (download, the actor's membership commits the server lacks, register, the rest); stranded heartbeat on a refused claim and after a complete pass without the head's read epoch, wrapped under the newest established secret; opens with any held secret, stamps, steps and token deletes only under established epochs.

## membership-flows
- Done (notes/node.md, Flows readings): `Engine::reseal_due` decides with node-sync's `SyncState::complete_pass`, skips roles whose newest is snapshot-established; stranded members are re-sealed by `reshare` (by hand or on a stranded heartbeat, node-sync) and over pairing; rotations box the timeline's current members; `/secrets` compaction is node-core's gate. Left: the removal's rotation uploaded before the step (node-sync).
