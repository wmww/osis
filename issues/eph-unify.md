# Ephemeral as a storage property: what is left
> Summary: Ephemeral data is ordinary data whose commits, bodies and index rows live in memory (Tess's direction: "ephemeral should be same as durable in almost every way"; built through the durable sync path, notes/ephemeral.md, `core/node/src/sync/memory.rs`). Left: E (durable automatic compaction, Tess's call) and the residuals below.
> Priority: normal
> Tags: ephemeral, design

Kept by design: memory storage itself, presence (author tie), ephemeral signals (relay-only), the restart reconcile, a node cap and host caps. What differs from durable: a memory commit's header is forgotten once spent (spec/commits.md §5); the rest is in notes/ephemeral.md (Divergences left).

## E. Durable automatic compaction
Durable data never compacts into snapshots: no API asks for it, and `SyncEngine::compact` is a hook only the sim calls. Its storage stays proportional to live data by the cover rule (an overwrite drops the bodies it covers), but each live write keeps its own body, while ephemeral aspects merge them into one snapshot automatically (the memory trigger, `Engine::memory_compactions`). The cost of doing the same for durable data: a snapshot cannot give back what it replaced (spec/commits.md §5 Covered, Limit), so a purge that later falls (its author's right judged invalid by a late role change) or another later correction could no longer restore the originals once they are compacted away. Tess's decision; give it its own `tess-call` issue when someone picks it up. Whether the sim-only hook stays is a test-tool question.

## Residuals
- **Reconnect burst**: over `MAX_GAINED` memory entries per label a new connection lists no `gained`, so every held body goes up again there once (a cap-sized burst per reconnect).
- **Unplaced bodies**: a memory body is deleted at a label for leaving its closure only by a node that judged or placed it while its thing was in the closure since the node started (`State::memory_in_closure`, spec/sync.md §9); bodies of an unplaced thing stay at a host if only other nodes remain.
- **Paging and a divergence**: issues/eph-unpaged-cover.md (memory deltas never page).
- **Undo of a covered live write**: undo runs on memory commits' kept history as durable undo does (notes/ephemeral.md Undo), but a live own write covered by a compaction snapshot is forgotten with its header (spec/commits.md §5), so its undo is then an unknown commit. The compaction trigger leaves an aspect its thing keeps history for alone while only kept bodies sit beside its one live write; an aspect with several live writes (map entries written apart) or none kept compacts them away. Durable compaction drops a live body likewise (`NotUndoable{ContentGone}`), explicitly. Closing it means keeping a covered live body (or its header and delta) while undo may reach it, a retention rule for both classes.
