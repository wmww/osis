# Signals: ephemeral data for event-stream apps
> Summary: Owner wants osis usable for event-stream-like apps (signals), not just shared state. Open: whether create-then-delete patterns suffice or signals need first-class support or standard patterns. Discussion queued, not started.
> Tags: sync, data-model, api, crdt

## Idea (owner, 2026-10-12)
Some apps look more like event streams than shared databases. There should be a way to make ephemeral data so they can use the same osis infra.

Most basic form, needing nothing new:
- create a thing carrying the signal data and immediately delete it, or
- set and reset a signal aspect on a long-lived channel thing.

Owner's hunch: thinking about this now, in the architecture phase, and adding first-class support (or at least standard patterns) will make everyone's lives easier. But no architecture cruft for its own sake: if existing mechanisms truly handle the use case, a documented pattern is enough.

## Related
- `ephemeral` aspect flag proposal, retention class `purge` (notes/data-model.md, notes/crdt-sync.md).
- Cross-author resets of ephemeral content at blind nodes (issues/deletion-rights.md §1).
- Sync cost goals and drop-list compaction (notes/constraints.md, notes/sync.md).
- Listener semantics (notes/api.md).
