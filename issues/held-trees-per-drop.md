# Judging a dropped chunk walks every held body of its thing
> Summary: `dropped_chunks` asks `Engine::held_trees(tid)`, which decodes (from cache) and clones every held part on every aspect of the thing and walks all their trees; the cache goes at every changing transaction, so each pass with chunk candidates pays O(held bodies of the thing + their tree nodes). Measured: one or two misses per write-and-compact of a large value, each walking n+4 parts with n other held bodies on the thing (14 at n=10, 104 at n=100). Rare today; per large-value write once compaction is automatic.
> Priority: normal
> Tags: engine, node, sync

- The rule (spec/sync.md §7: a chunk goes only once no held body or live state of the thing links it) is right; the cost is that it is recomputed from scratch, and over the whole thing, not what changed.
- Bound: an index blob → held bodies linking it (`(commit, ai)`), kept as `ix.by_chunk` is: filled when a body is stored (its delta's roots, through held node blobs, extended as node blobs arrive), emptied as it drops. A candidate is then O(log) and needs no walk; `missing` stays per body.
- Simpler step first: cache each body's linked trees per record write (as `Core::bodies` keeps `body_links`), so a miss is a union of cached sets, no decode, clone or walk.
- Residue it widens: a held body's tree node no reachable host holds keeps every dropped chunk of its thing waiting for good (notes/engine-paged.md, Residue).
