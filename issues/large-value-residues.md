# Large values: residues after chunk reuse
> Summary: Chunk reuse makes an edit upload O(change), but chunks linked and not listed (reused, or under a compaction snapshot) are never uploaded under a new label, list `edit` items are not chunked, and a node lacking a tree's node blobs never shreds that thing's dropped chunks.
> Tags: performance, node, storage, sync

Repro: code reading, no failing test (each item names its function).

1. **Linked but unlisted chunks under a new label** (`sync/pass.rs` `chunk_blobs` = the header's chunk list). A body's chunk blobs go up with it, but a reused chunk is listed only by the commit that introduced it, and a compaction snapshot lists none of the chunks its values link. Under the same label they are already there; under a new one (label replacement, a thing moving into another group, spec/sync.md §3 closure) a reader gets the links without the blobs. Fix: a writer uploads with a body the trees its aspects' live states link (`Engine::live_trees`), not only the listed chunks.
2. **`edit` items not chunked** (`engine/large.rs` `chunk_op`): `Op::Edit { base, new }` passes large list items through unchunked, so a sequence edit inserting one writes it inline. Fix: chunk `new`'s items as an `insert`'s, matching `base` by content hash.
3. **Lazy nodes keep dropped chunks** (`Engine::live_trees` returns `None` when a node blob is not held, and `dropped_chunks` then keeps every candidate of the thing): a node that never fetched a value's tree never deletes that thing's dropped chunks at servers or locally; another right holder that holds the tree does. Fix if it matters: fetch the missing node blobs before judging.
