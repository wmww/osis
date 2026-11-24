# Durable deltas decode with no memory bound
> Summary: Tess's decision B (per-blob item cap `MAX_PAGE_ITEMS`, then verify and join page by page) is built (steps 1-5, plus root tables paged like element arrays, notes/crdt.md Wire): a 10^6-key map's commit or snapshot applies in 0.23-0.35 GB; every reader of a stored paged state reads it a page at a time through one reader (notes/engine-paged.md), and a write replacing or removing a whole position holds about a page. The writer side is done; left are two readers: `covered` of a body paged below a map entry, and tree roots of a nested paged state, read whole.
> Priority: low
> Tags: security, crdt, engine

The steps cited from code: 1-2 streaming re-encode and piece iterator (osis-crdt `stream.rs`, notes/crdt.md Wire), 3 engine apply per piece (notes/engine-paged.md Streamed apply), 4 streamed readers of held parts (Streamed readers), 5 encoder pages as elements come (`codec::Pager`). Target: memory about one decoded page plus the state pages touched, the store transaction's 16 MiB spill buffer, and a few bytes per element of tracking.

## Whole at the writer, within the rule (10^6 keys)
- The delta: the op API takes whole `Value`s (`Mutation::set`) and `DeltaBuilder` resolves the ops into one fragment, so the writer holds the input value (about 0.4 GB with the step's clone) and the delta (`approx_bytes` 1.9 GB: about 1.9 KB per entry of an int key and int value, a representation cost of `Map`'s records and key index). That is a fixed multiple (about 5x) of what the app handed over, within the rule; a streamed write API would need ops built and encoded page by page.
- A `set` of a whole collection loads it whole: it writes the difference (spec/crdt.md §9), so its delta names every live record of each key or value it removes, O(the old state's entries) however small the new value. A replace or removal of the position is the bounded way (notes/engine-paged.md, Whole-position writes).

## Measured (`memory::big_map_apply_memory`, release, in-memory stores, 10^6 keys)
Commit / snapshot with pages 21 / 22 MB. Write 2.2 GB, 135 s; a node holding the thing applies 0.23 GB, 276 s; a node applies the snapshot alone 0.35 GB, 224 s; about 0.23-0.26 GB of each is what the store keeps. Box at load 25-60, so times only roughly comparable. The snapshot's writer (a page at a time) is not among these figures.

## Left whole at a reader
- `covered` of a body paged below a map entry: one group, the body whole (`Fragment::positions_at` takes the snapshot's whole record at an entry, so a group of its pages meets every other group's writes there). Splitting it needs `positions_at` to descend into a record's content.
- Tree roots of a state with a collection paged inside another's elements (`osis_crdt::each_piece` with keys: `None`): read whole. A key's records on two pages of the outer map each hold their own inner pages, so an inner page read as the whole reads it needs the key's other records and their inner pages' records of its keys, recursively.

## Also not streamed
- Role-class bodies stay whole (rosters of thousands, not millions). Not streamed: paged positions inside a `Slots` slot, a sequence element's content or a page; paged sequences at apply; a reset over nested paged collections.

Store transaction memory is bounded already (the pager spills past `StoreConfig::spill_bytes`, 16 MiB).
