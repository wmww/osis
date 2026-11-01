# A crash before a self-removal is placed keeps the lost secrets for good
> Summary: node-sync drops what a self-removal lost once it is placed (`drop_when_idle`, `sync/deliver.rs::take_done_lost`), but that flag is memory only and local commits never add to the durable `l/` work list (`apply/atomic.rs`, `Origin::Local`). A crash after the self-removal lands and before the drop leaves the node holding the left actor's secrets and content after restart, until some unrelated received roster change reaches them or the app calls `drop_lost`: against spec/permissions.md §3 (a node that learns it lost read access MUST drop).
> Tags: security, node

## Notes
- Same shape as the purge crash window fixed on store-audit (memory-only follow-up after a durable change); the startup `forget_dropped(None)` sweep does not cover it (it handles dropped deltas only).
- Simple fix candidate: `SyncEngine::new` starts with `drop_when_idle = true` (one full `drop_lost` at the first idle moment with a connection up). `placed` is derived from stored state, so idle after restart should mean placed; check that, and that it is cheap (`lost_among` over held actors). It also catches losses by `until` with no role commit (notes/node.md "Not triggered").
- Unverified, related: a flow's `Done` (First/Certificate/Removal placements) is memory only too; a crash between the commit and `carry_out` loses them (inbox deliveries are safe: `note_unsent` in the commit's transaction). Check whether a later pass places a self-removal anyway.
- Test: self-removal offline, restart, connect, settle; the left actor's secrets and a content marker are gone.
