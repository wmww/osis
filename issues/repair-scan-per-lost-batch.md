# Chunk repair: not wired, and a closure scan per lost batch
> Summary: Chunk and tree-node repair (spec/sync-ids.md §1 Repair) has no caller in the rebuilt sync: `Engine::relink` is reached only by an engine test. When it is wired, mind its cost: it finds the aspects linking a lost blob by asking each thing of the closures that lost it whether its live states link it (memoized walks), so a peer reporting held chunks gone, batch after batch, costs O(closure things) per batch.
> Priority: normal
> Tags: sync, engine, security

- Where: `Engine::relink` (core/engine/src/engine/large.rs) loops `tree_refs::state_refs_in` over the things given; lookups in `Core::tree_refs` per thing (walks are memoized).
- Wiring it: the facade exposes the lost blobs' repair as a command the read module runs when a body's linked blob is gone at every source; a per-aspect back-off gates the rewrite.
- Cost options: skip blobs already judged linked since the last batch, or rate the scan by the same back-off as the rewrite.
