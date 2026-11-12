# Ephemeral as a storage property: what is left
> Summary: Ephemeral data is ordinary data whose commits, bodies and index rows live in memory (Tess's direction: "ephemeral should be same as durable in almost every way"; built through the durable sync path, notes/ephemeral.md, `core/node/src/sync/memory.rs`). Left: E (durable automatic compaction, Tess's call); the ephemeral differences still to remove are issues/eph-parity.md.
> Priority: normal
> Tags: ephemeral, design

What follows from memory and the one rule kept beyond it: notes/ephemeral.md (What follows from memory, Superseded expiring writes).

## E. Durable automatic compaction
Durable data never compacts into snapshots: no API asks for it, and `SyncEngine::compact` is a hook only the sim calls. Its storage stays proportional to live data by the cover rule (an overwrite drops the bodies it covers), but each live write keeps its own body, while ephemeral aspects merge them into one snapshot automatically (the memory trigger, `Engine::memory_compactions`). The cost of doing the same for durable data: a snapshot cannot give back what it replaced (spec/commits.md §5 Covered, Limit), so a purge that later falls (its author's right judged invalid by a late role change) or another later correction could no longer restore the originals once they are compacted away. Tess's decision; give it its own `tess-call` issue when someone picks it up. Whether the sim-only hook stays is a test-tool question.
