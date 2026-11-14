# Honest status and waits: leftovers
> Summary: Status, `wait_synced` and history `complete` judge each sync ID by its sources, the connections up now with it open (built, notes/api.md Sync configuration and status). Left: `Refused` still names saved peers answering 14, to be replaced by issues/net-shared-set.md's judged holder; and a `Thing` wait that begins after its thing was left and forgotten runs to its timeout. Part of issues/sync-rewrite.md.
> Priority: low
> Tags: api, node, sync

- **`Refused`** (`SyncState::Refused`, `refused_by` in core/node/src/sync/status.rs) names hosts this node holds to serve the group that answer 14 or are full. Under one kind of peer (issues/sync-rewrite.md) it names a connected node the shared set judges a holder that refuses.
- **Forgotten before the wait**: a `leave` that lands and forgets before a `Thing(t)` wait begins reads as never carried, so the wait runs to its timeout (a spurious CLI exit 6). Nothing tells a forgotten thing from one never held. Ending the wait whenever nothing carries `t` and no role is held closes it, but also ends a wait on a thing that has not arrived yet.
