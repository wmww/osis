# Repair asks every thing of the closure on each lost-blob batch
> Summary: `Engine::relink` finds the aspects linking a lost blob by asking each thing of the closures that lost it whether its live states link it (memoized walks). A host reporting held chunks deleted, batch after batch, costs O(closure things) per batch; the per-aspect back-off gates only the rewrite.
> Priority: low
> Tags: engine, node-sync, security

- Where: `SyncEngine::relink_lost` (core/node/src/sync/inbound.rs) runs at the label's next settled pass after a batch with a lost blob, and again at each later pass of the label while a pending commit's aspect holds a candidate back (at least once per resync, the label being unsettled; a commit pending for good, e.g. a writer's paged delta whose page never comes, repeats it for good); a label only the back-off holds is not scanned again before it passes; `Engine::relink` (core/engine/src/engine/large.rs) loops `tree_refs::state_refs_in` over the closure.
- Bound: lookups in `Core::tree_refs` per thing (walks are memoized), so cost is like a full pass's; only a host that is the label's only host can trigger it (the blob must be gone from every host).
- Options: skip blobs already judged linked since the last batch, or rate the scan by the same back-off as the rewrite.
