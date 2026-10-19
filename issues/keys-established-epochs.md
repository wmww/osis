# Established epochs: what node-core, node-sync and membership-flows must implement
> Summary: spec/crypto.md §4 "established" is the one notion behind current epochs, history boxes, re-seal and registration. osis-keys implements it (notes/crypto.md, osis-keys bullet); these are the obligations of its callers.
> Tags: keys, crypto, permissions, sync

## node-core
- Done (notes/node.md, Established epochs): `applied`, `snapshot_keyed`, `unset_applied`, persistence, compaction gate, headers kept.
- Retention: before dropping a body with live writes (keep-at-most bound, at most 0, timed) a writer writes a covering snapshot when it holds none (spec/commits.md §5); the deletion queue entry for a timed delete carries "snapshot first".
- Carrier tiebreaks of spec/sync.md §7 (identical body: higher blob ID goes; covered-equal snapshots: higher commit ID goes).

## node-sync
- Per (label, server/peer) a "pass complete" event (log read to its end, `more = false`); `complete_pass(actor)` = complete at every server and peer it syncs the actor's labels with since the last membership commit of the actor applied from elsewhere.
- Re-registration order: download, then upload the actor's membership commits the server lacks under the head's keys, then register, then everything else (spec/sync.md §5).
- Stranded heartbeat: after a complete pass at that server when the head's epoch cannot be opened, or on a refused claim; wrapped under the newest established secret.
- Opens with the sync key of any held secret (an unestablished one included); stamps and deletes only with established epochs.

## membership-flows
- Done (notes/node.md, Flows readings): `Engine::reseal_due` decides with node-sync's `SyncState::complete_pass`, skips roles whose newest is snapshot-established; stranded members are re-sealed by `reshare` (by hand or on a stranded heartbeat, node-sync) and over pairing; rotations box the timeline's current members; `/secrets` compaction is node-core's gate. Left: the removal's rotation uploaded before the step (node-sync).
