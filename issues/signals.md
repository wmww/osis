# Signals: ephemeral data for event-stream apps
> Summary: Owner wants osis usable for event-stream-like apps (signals), not just shared state. Agent proposal 2026-10-14: one core addition (capped labels: a blind node keeps only the newest K entries) plus single-writer channel conventions; create-then-delete rejected. Awaiting owner.
> Tags: sync, data-model, api, crdt

## Idea (owner, 2026-10-12)
Some apps look more like event streams than shared databases. There should be a way to make ephemeral data so they can use the same osis infra.

Most basic form, needing nothing new:
- create a thing carrying the signal data and immediately delete it, or
- set and reset a signal aspect on a long-lived channel thing.

Owner's hunch: thinking about this now, in the architecture phase, and adding first-class support (or at least standard patterns) will make everyone's lives easier. But no architecture cruft for its own sake: if existing mechanisms truly handle the use case, a documented pattern is enough.

## Analysis (agent, 2026-10-14)
Two kinds: latest-wins (presence, cursors, sensor reading) and every-event (presses, commands). Both ephemeral: no history, a returning receiver must not pay for its absence.

- Create-then-delete a thing: new identity per event, so every tracker keeps a reset tombstone per thing forever (no tombstone GC in v1); two commits per event; delete time is a guess. Rejected for streams.
- Set/reset on a single-writer channel: constant state, right shape for latest-wins. Fails on sync, not state: every signal is a blob that blind nodes store and every tracker downloads, even one returning after an hour; with `purge` the writer also sends a retire per write. Nothing blind lets a server drop stale signals.

## Proposal
Core, one addition: **capped labels**. A group thing's label policy (where the grace period lives) may carry a cap K. A node (blind or trusted) keeps only the newest K entries under that label, drops older immediately, no bin, no generation bump, no writer retire. Leaks nothing new (arrival order and counts are already visible). A capped group's blobs are labeled only under capped labels, never under uncapped ancestors, so a presence group may nest inside a document group. A reconnecting sender uploads only its newest K. Cursor protocol unchanged: dropped entries are not served; fallback reconciliation over a capped label is at most K entries.

Conventions, per channel:
- Single writer per channel (thing or map key per sender). Makes resets safe without causal contexts.
- Latest-wins: LWW register; K about senders times burst, or a label per sender with K=1 when a quiet sender must not be pushed out.
- Every-event: single-writer list, events carry a sender seq; receivers keep last seen seq locally and dedupe; writer prunes by element delete or whole-aspect replace (safe, sole writer). Receiver state bounded by the prune window.
- Retention `undefined` normally, `purge` for sensitive content; the cap bounds storage, purge adds the forward-secure guarantee.
- Inbox/command queue for offline recipients is state, not a signal: receiver-owned list, senders append, owner deletes elements (not reset: a reset drops a late concurrent append).

Not added: event commit kind, delivery guarantees, new CRDT. `channel<T>` sugar belongs to the API phase.

Costs: a signal is a full commit (about 250 B with wrap and token hash); at 10 Hz per user a few KB/s. Latency bounded by sync round trip; live signals need push on a subscribed connection (transport, open in notes/sync.md, not signal-specific).

## Open for owner
1. Cap per label (preferred) or per opaque slot in entry metadata (per-sender guarantee in one label, leaks sender count)?
2. Capped groups excluded from ancestor labels (removes a usage rule) or standalone by convention?
3. Are cursor-rate streams in scope, or notification-rate only? Decides whether the commit floor matters.

## Related
- `ephemeral` aspect flag proposal, retention class `purge` (notes/data-model.md, notes/crdt-sync.md).
- Cross-author resets of ephemeral content at blind nodes: resolved, any current writer hard-deletes by writer-derived token (notes/sync.md, Authorization).
- Sync cost goals and drop-list compaction (notes/constraints.md, notes/sync.md).
- Listener semantics (notes/api.md).
