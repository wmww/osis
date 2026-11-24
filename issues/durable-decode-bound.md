# Durable deltas decode with no memory bound
> Summary: Tess's decision B (per-blob item cap `MAX_PAGE_ITEMS`, then verify and join page by page) is built (steps 1-5, plus root tables paged like element arrays, notes/crdt.md Wire): a 10^6-key map's commit or snapshot applies in 0.23-0.35 GB; `covered`, presence and tree roots read a piece at a time (notes/decode-bounds.md). A snapshot's writer and its sweep read the stored state a page at a time (notes/engine-paged.md, The snapshot writer). Left: a write replacing a whole position loads its state whole, compaction's `snapshot_cost` encodes the snapshot unpaged, and `covered` of a body paged below a map entry and roots of a nested paged state read whole.
> Priority: low
> Tags: security, crdt, engine

The steps cited from code: 1-2 streaming re-encode and piece iterator (osis-crdt `stream.rs`, notes/crdt.md Wire), 3 engine apply per piece (notes/engine-paged.md Streamed apply), 4 streamed readers of held parts (Streamed readers), 5 encoder pages as elements come (`codec::Pager`). Target: memory about one decoded page plus the state pages touched, the store transaction's 16 MiB spill buffer, and a few bytes per element of tracking.

## Left whole at the writer (10^6 keys)
- The delta: the op API takes whole `Value`s (`Mutation::set`) and `DeltaBuilder` resolves the ops into one fragment, so the writer holds the input value (about 0.4 GB with the step's clone) and the delta (`approx_bytes` 1.9 GB: about 1.9 KB per entry of an int key and int value, a representation cost of `Map`'s records and key index). That is a fixed multiple (about 5x) of what the app handed over, within the rule; a streamed write API would need ops built and encoded page by page.
- A write of a whole position (`set` of a collection, `Tx::load_for_ops` with no paths) loads the state there whole, however small the new value: the builder resolves against the whole old state. Bounding it needs the builder to reset against the skeleton and leave the pages to the apply's page-by-page reset (`pages::join_reset`).
- Compaction's `snapshot_cost` (the weight of the snapshot it would write) encodes it unpaged through the page walk: the encoded bytes whole, O(encoded state). A sink counting page bytes would bound it.
- `covered` of a body paged below a map entry: one group, the body whole (`Fragment::positions_at` takes the snapshot's whole record at an entry, so a group of its pages meets every other group's writes there). Splitting it needs `positions_at` to descend into a record's content.
- Role-class bodies stay whole (rosters of thousands, not millions). Not streamed: paged positions inside a `Slots` slot, a sequence element's content or a page; paged sequences at apply; a reset over nested paged collections.

## Measured (`memory::big_map_apply_memory`, release, in-memory stores, 10^6 keys)
Commit / snapshot with pages 21 / 22 MB. Write 2.2 GB, 135 s; a node holding the thing applies 0.23 GB, 276 s; a node applies the snapshot alone 0.35 GB, 224 s; about 0.23-0.26 GB of each is what the store keeps. Box at load 25-60, so times only roughly comparable. The snapshot's writer (a page at a time) is not among these figures.

## Left whole at a reader
- Tree roots of a state with a collection paged inside another's elements (`pages::each_piece` with keys: `None`): read whole, as a key's records then reach into pages below.

Store transaction memory is bounded already (the pager spills past `StoreConfig::spill_bytes`, 16 MiB).
