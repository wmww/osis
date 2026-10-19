# Established epochs: what node-core, node-sync and membership-flows must implement
> Summary: spec/crypto.md §4 "established" is the one notion behind current epochs, history boxes, re-seal and registration. osis-keys implements it (notes/crypto.md, osis-keys bullet); these are the obligations of its callers.
> Tags: keys, crypto, permissions, sync

## node-core
- On applying a valid commit with a `/secrets` write: `SecretsWrite::applied(epochs, (keys_write, keys_before))` (keys_write empty when it writes no `/keys`); on a held `/secrets` compaction snapshot (pages joined): `snapshot_keyed`; on a commit found invalid later: `unset_applied` + `establish`. Persist `established`, `applied`, `snapshot` per epoch (the store's epochs encoding; never re-infer from state on load). A plain thing's view is `derived` from the owner's. Keep headers of applied commits (spec/commits.md §5).
- Retention: before dropping a body with live writes (keep-at-most bound, at most 0, timed) a writer writes a covering snapshot when it holds none (spec/commits.md §5); the deletion queue entry for a timed delete carries "snapshot first".
- Carrier tiebreaks of spec/sync.md §7 (identical body: higher blob ID goes; covered-equal snapshots: higher commit ID goes).

## node-sync
- Per (label, server/peer) a "pass complete" event (log read to its end, `more = false`); `complete_pass(actor)` = complete at every server and peer it syncs the actor's labels with since the last membership commit of the actor applied from elsewhere.
- Re-registration order: download, then upload the actor's membership commits the server lacks under the head's keys, then register, then everything else (spec/sync.md §5).
- Stranded heartbeat: after a complete pass at that server when the head's epoch cannot be opened, or on a refused claim; wrapped under the newest established secret.
- Opens with the sync key of any held secret (an unestablished one included); stamps and deletes only with established epochs.

## membership-flows
- Re-seal: at the end of a complete pass, `reseal_member` for members `reseal_needed` reports, and for stranded heartbeats; when `newest_is_snapshot` do not re-seal (optionally rotate).
- Rotation: boxes for members current in the timeline (`rotate` keeps history to established secrets); a removal's rotation uploaded before the step (node-sync does the ordering).
- `/secrets` compaction only when `may_compact_secrets`.
