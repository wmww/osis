# A node restored from a backup reuses node-form counters and voids its own commits
> Summary: node-form dots are `(node, counter)` with counters from the local store; a store restored from a backup (phone backup/restore, VM snapshot, file copy) keeps the node's signing seed but an old counter, so its next commits overlap the counters of everything it wrote between backup and restore, and spec/commits.md §4 voids both the old and the new commit on every aspect touched, at every node, silently. The spec says such a node "must not write node-form dots" but nothing detects the state.
> Tags: security, engine, crdt, node, spec

Mechanism: `Store::reserve_counters` hands out `counter(tid, ak)` from the store; `apply/` has no check that an own-authored commit arriving from a server carries counters at or above the store's next (grep of `core/engine/src/apply` for own-author handling finds only test hooks). The overlap rule (two node-form commits of one node with overlapping ranges on one aspect are both invalid) exists against a revoked actor's dot reuse; an honest restore hits it with the same signature key, so there is no forgery to detect and nothing heals it short of the user rewriting the data. Two devices restored from one backup are the same failure, ongoing.

Common on consumer platforms: iOS/Android app-data backup restored onto a new phone, desktop file-level backups, container/VM snapshots.

Fix directions (no wire change):
- Detect at sync: when a node receives an own-authored node-form commit whose counters on `(tid, ak)` are at or above its reserved next, mark that aspect (or the whole node) "unsure" and write it in commit form from then on (spec/crdt.md §2.1 already allows). Closes the window after the first reconcile; writes made offline between restore and that reconcile still overlap.
- Conservative: after an open that cannot prove continuity (a store generation counter checked against the newest own commit seen at each server, or simply any open on a copied store), use commit form on every aspect until each synced label has been reconciled once.
- Store a random store-instance id in the persisted sync state and in a per-server record (the server already keeps per-connection nothing stable; the node could keep its last-seen own commit per aspect in the store, which a restore rolls back too, so detection must come from the server's log, not local state).

Repro to write: two nodes from one store copy (or a store rolled back after N commits synced), both write the same aspect, sync through a hub; expect both commits invalid everywhere.
