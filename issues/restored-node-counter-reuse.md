# A node restored from a backup reuses node-form counters and voids its own commits
> Summary: node-form dots are `(node, counter)` with counters from the local store; a store restored from a backup (phone backup/restore, VM snapshot, file copy) keeps the node's signing seed but an old counter, so its next commits overlap the counters of everything it wrote between backup and restore, and spec/commits.md §4 voids both the old and the new commit on every aspect touched, at every node, silently. The spec says such a node "must not write node-form dots" but nothing detects the state.
> Tags: security, engine, crdt, node, spec

Mechanism: `Store::reserve_counters` hands out `counter(tid, ak)` from the store; `apply/` has no check that an own-authored commit arriving from a server carries counters at or above the store's next (grep of `core/engine/src/apply` for own-author handling finds only test hooks). The overlap rule (two node-form commits of one node with overlapping ranges on one aspect are both invalid) exists against a revoked actor's dot reuse; an honest restore hits it with the same signature key, so there is no forgery to detect and nothing heals it short of the user rewriting the data. Two devices restored from one backup are the same failure, ongoing.

Common on consumer platforms: iOS/Android app-data backup restored onto a new phone, desktop file-level backups, container/VM snapshots.

## Recommended fix
Make "sure of its last counter" (spec/crdt.md §2.1) a concrete, local predicate and act on it by default, instead of trying to detect a restore:
1. **Commit form until caught up.** After every open, a node writes an aspect in commit form until the thing's labels have each completed one pass since the open (reconciled and read to the end at a server, and at the co-readers it is connected to: the existing complete-pass notion of spec/permissions.md §3). A thing in no labeled closure is always sure (nobody else can hold its commits). Cost: the first commits after each app launch are commit form (one 32-byte source entry per foreign commit referencing them, no run continuation into them); typing sessions commit every few seconds, so this is a handful of commits per launch.
2. **Adopt counters from what the pass shows.** During the pass the engine records, per (aspect, own node), the greatest own counter it sees in own node-form commits and in valid snapshot frontiers for its node; the store's next counter becomes `max(stored, seen + 1)` before node form resumes. Frontiers are claims, but a claim about the node's own counters by a valid snapshot is already counted as received (spec/crdt.md §8), and over-adopting only skips counters.
3. Spec: replace the §2.1 sentence with the predicate above; spec/commits.md §4 unchanged (the overlap rule stays as the backstop against revoked actors).
Residual: a commit that reached only a peer the node never reconciles with before writing node form. Narrow, and the same loss as today.

Rejected: a store-instance id checked against a server record (the server keeps nothing per client, by design); always commit form (text runs across commits and frontier size depend on node form).
