# Large values: chunk trees, links, dedup by reuse, streaming, pages as blobs, frontiers by link
> Summary: Implement spec/data-model.md §6 and the blob side of spec/crdt.md §8: content-defined chunking of large atomic values into link trees, chunk and tree-node blobs under random keys with the creating delta's tokens, keyed link content hashes and hash-based equality, dedup by reuse against the current tree with the re-encryption rule, lazy fetch and streaming reads bounded in memory, pages of any paged delta or snapshot and revoke frontiers as blobs, and CHUNK_THRESHOLD enforcement in the write path.
> Tags: data-model, crdt, sync, storage, tests

Crates: `osis-label` (module `chunks`), `osis-crdt` (`PageSink`/`PageSource` adapters), `osis-node` (write path and fetch), `osis-store` (chunk cache units). Depends on: core (chunker, Link), crypto, label, commit (chunk list), store, node-core. Unblocks: api large-value surface, sim scale tests.
Spec: spec/data-model.md §6–§7, spec/crdt.md §8, spec/sync.md §1 (chunk reuse and re-encryption), §6 (lazy chunk fetch; pages before commit apply), spec/crypto.md §6–§7 (link, chunk tokens), spec/commits.md §1 (chunk list, frontier link), spec/requirements.md (Scale: no whole value in memory; Data model: large values compare by content hash). Notes: notes/local-store.md (dedup by reuse, shredding of versions), notes/data-model.md (Large values). Spec trumps this plan.

## Deliverables
- Chunk tree builder: streaming input of canonical bytes → leaves by the shared chunker, interior nodes as canonical arrays of links (fan-out from `format`, every node ≤ `MAX_BLOB`), each blob framed with a prefix carrying the delta's expiry and token commitments (chunk tokens from the prefix salt), fresh random key, `Link {content hash = kdf("link", dedup secret, canonical value), blob id, suite||key}`; root link placed in the enclosing value; the commit's chunk list with token hashes.
- Reader: `open_link(link) -> impl Read/AsyncRead` fetching blobs lazily via `BlobFetch`, verifying each node and the final content hash; range reads for text and bytes; a bound on in-memory buffering (one chunk plus the path).
- Dedup by reuse: when writing a new version, match new chunks by keyed content hash against the current tree's links and reuse (ID, key) unless the chunk's expiry is earlier than the new delta's or its thing-secret tokens differ (then re-encrypt); measure reuse ratio in a test.
- Equality of large values by content hash (set elements, map keys, register diff) in crdt/schema paths; two writes of equal content produce different link bytes (spec/requirements.md, Data model).
- Thresholds: above `CHUNK_THRESHOLD` must chunk, below must not (write validation in node/schema); a frontier above the threshold goes by link (commit header).
- Paging adapters: `PageSink`/`PageSource` over blob framing and fetch for paged deltas and snapshots; pages fetched before their commit applies (node-core hook).
- Store: chunk and tree-node plaintext cache units per aspect (droppable, rebuildable); shredding a version drops its wrap and the keys only it reached (via links) — test that an old version's chunks are unreadable after purge while shared chunks still read through the live tree.

## Steps
- [x] Builder/reader with in-memory `BlobFetch`; property: round trip for random sizes incl. empty and exactly-threshold; memory bound test with reduced constants.
- [x] Tokens on chunks and re-encryption rule; dedup test; equality-by-hash integration in crdt/schema.
- [x] Paging adapters + node hooks (pages before apply); frontier by link in flows (frontier links: issues/flows-gaps.md).
- [ ] Node write path: large register/blob/string, large set element and map key; API streaming hooks; sim scale scenario (a value of many chunks edited by two nodes; O(change) transfer measured, tier 2).

## Done when
A value larger than memory (simulated by small constants) round-trips through two nodes and a server with O(change) bytes per edit (tier-2 budget ≈1.2x); purge of a version shreds only its unique chunks; notes/data-model.md updated. Delete this plan.

## Progress
- Session 1 (library, osis-label): steps 1–2 done; step 3 library part done (page params on `BlobWriter`/`BlobReader`, paged snapshot through blobs, `osis_crdt::page_array`, `chunker/pages.vec`). Left for node integration (wave 4): store-backed `BlobStore` adapter, pages-before-apply hook (fetch on `Missing` or prefetch the commit chunk list), frontier by link in flows, step 4 write path and sim scale scenario, purge/shredding test, chunk cache units. Value equality by link hash moved into `osis_core::Value`. issues/large-value-seek.md.
- Node integration (waves 4-5): store-backed blob adapter (`engine/blobs.rs`), chunking in the write path (`engine/large.rs`: blobs, strings, set elements, map keys), pages fetched before apply (sync), API `stream`/`len`/`set_stream`. Left (issues/node-core-gaps.md, Large values): chunk reuse from the current tree, `Insert` items unchunked, dropped deltas' chunk blobs kept locally, the O(change) sim scale scenario (tier 2) and the purge-shreds-unique-chunks test; seeking: issues/large-value-seek.md.
