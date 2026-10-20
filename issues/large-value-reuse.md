# Large values: no chunk reuse, so an edit re-sends the whole value
> Summary: The node chunks large values but never reuses chunks of the current tree (osis-label's `BlobWriter::reusing` exists, the node does not call it), so editing a multi-GB value re-encrypts and uploads every chunk: O(value), not O(change) (spec/requirements.md Scale, Cost). Also `Insert` items of lists are not chunked, dropped deltas' page and chunk blobs stay in the local blob area, and the O(change) scale scenario and the purge-shreds-only-unique-chunks test are not written.
> Tags: performance, node, storage, data-model

Repro: no failing test: osis-node `engine/large.rs` `chunk_op` writes every tree into a fresh sink, never a reusing one; the library reuse is tested by osis-label `chunks::tests::dedup_by_reuse`.

Left from plans/large-values.md (deleted; library, paging, node write path, pages-before-apply and the API `stream`/`len`/`set_stream` are done, notes/data-model.md and notes/node.md):
- Reuse in the write path: match new chunks by keyed content hash against the current tree's links and reuse (ID, key) unless the chunk expires earlier than the new delta or its thing-secret tokens differ (spec/sync.md §1). Watch issues/rereview-residues.md item 4 (a purged chunk racing a reuse).
- `Insert` items of lists above `CHUNK_THRESHOLD` (written unchunked today).
- Delete page and chunk blobs of dropped deltas from the local blob area.
- Tier-2 sim scenario: a value of many chunks (small constants) edited by two nodes through a server, bytes per edit within about 1.2x of the change.
- Test: purging one version shreds only its unique chunks; shared chunks still read through the live tree.
- Seeking: issues/large-value-seek.md.
