# A collection too big for two page levels fails every snapshot of its aspect, locally
> Summary: the crdt encoder refuses an array whose link list needs a third page level (`codec::link_list`, `Error::Mismatch`, local class); nothing bounds a collection's total size (each delta is bounded, the state is their join), so any writer, or honest growth, past roughly 1-5 GB in one collection makes every writer node's compaction snapshot of the aspect fail, and `Engine::compactions` returns at that error each tick, leaving every aspect weighed after it uncompacted.
> Priority: normal
> Tags: crdt, engine, security

- Bound: top list at most `PAGE_TARGET` (64 KiB) of links of about 124-230 B (300-530 link pages), each link page up to 512 links (tree-node rule, about 256 on average), each page at least `CHUNK_MIN` (16 KiB): about 1 GB of one array's canonical bytes at the least, more on average. Decode bounds bound each delta and blob (notes/decode-bounds.md), not a state.
- Where: `engine/write.rs` `build` encoding a snapshot (compaction, `retention::compact` `weigh_due`: the error propagates; `compactions` re-queues the aspect and stops); `engine/state.rs` `encode` (whole states only). Paged states in the store are kept by the page index, not this encoder (not traced further).
- spec/wire.md §6 says only "A fragment needing a third level cannot be written". Options: more levels (the tree-node rule already generalizes, as chunk trees do); or a stated bound on a collection with writers refusing past it and snapshots leaving such an aspect uncompacted, never an error.
