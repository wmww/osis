# Durable deltas decode with no memory bound
> Summary: Tess's decision B (per-blob item cap `MAX_PAGE_ITEMS`, then verify and join page by page) is built (steps 1-5, plus root tables paged like element arrays, notes/crdt.md Wire): a 10^6-key map's commit or snapshot applies in 0.23-0.35 GB; `covered`, presence and tree roots read a piece at a time (notes/decode-bounds.md). Left: a snapshot's writer loads, clones and copy-indexes the whole state (2.3 GB), a write replacing a whole position loads its state whole, and `covered` of a body paged below a map entry and roots of a nested paged state read whole.
> Priority: low
> Tags: security, crdt, engine

The steps cited from code: 1-2 streaming re-encode and piece iterator (osis-crdt `stream.rs`, notes/crdt.md Wire), 3 engine apply per piece (notes/engine-paged.md Streamed apply), 4 streamed readers of held parts (Streamed readers), 5 encoder pages as elements come (`codec::Pager`). Target: memory about one decoded page plus the state pages touched, the store transaction's 16 MiB spill buffer, and a few bytes per element of tracking.

## Left whole at the writer (10^6 keys)
- The delta: the op API takes whole `Value`s (`Mutation::set`) and `DeltaBuilder` resolves the ops into one fragment, so the writer holds the input value (about 0.4 GB with the step's clone) and the delta (`approx_bytes` 1.9 GB: about 1.9 KB per entry of an int key and int value, a representation cost of `Map`'s records and key index). That is a fixed multiple (about 5x) of what the app handed over, within the rule; a streamed write API would need ops built and encoded page by page.
- A write of a whole position (`set` of a collection, `Tx::load_for_ops` with no paths) loads the state there whole, however small the new value: the builder resolves against the whole old state. Bounding it needs the builder to reset against the skeleton and leave the pages to the apply's page-by-page reset (`pages::join_reset`).
- The writer's snapshot (`Engine::snapshot`): loads and clones the whole state (+1.9 GB) and encodes it a page at a time. Its local apply joins it a piece at a time (a valid snapshot's copies are never compared with the state). Encoding from the paged state a page at a time (the encoder pulling each paged position's state pages, twice for the collecting pass; expiring values stripped per page; `sources_of` and `facts_of` folded over the pieces) would save the load and clone: the page-pulling encoder (the `Track` path walk the check already has, plus an engine page source over `StatePages` in wire order, `Tx::each_piece` the walk).
- `covered` of a body paged below a map entry: one group, the body whole (`Fragment::positions_at` takes the snapshot's whole record at an entry, so a group of its pages meets every other group's writes there). Splitting it needs `positions_at` to descend into a record's content.
- Role-class bodies stay whole (rosters of thousands, not millions). Not streamed: paged positions inside a `Slots` slot, a sequence element's content or a page; paged sequences at apply; a reset over nested paged collections.

## Measured (`memory::big_map_apply_memory`, release, in-memory stores, 10^6 keys)
Commit / snapshot with pages 21 / 22 MB. Write 2.2 GB, 135 s (snapshot 2.3 GB, 277 s); a node holding the thing applies 0.23 GB, 276 s; a node applies the snapshot alone 0.35 GB, 224 s; about 0.23-0.26 GB of each is what the store keeps. Box at load 25-60, so times only roughly comparable.

## Left whole at a reader
- Tree roots of a state with a collection paged inside another's elements (`pages::each_piece` with keys: `None`): read whole, as a key's records then reach into pages below.

Store transaction memory is bounded already (the pager spills past `StoreConfig::spill_bytes`, 16 MiB).

## Parked: a page-walking snapshot writer (branch `mizzen-snapshot-stream`, 4e60f9b08)
A snapshot encoder pulling stored pages in wire order was built and reviewed twice, then parked. What it taught:
- Stripping expiring values does not commute with paging: an expiring write inside a keyed map record moves to that dot's key-erased record (the branch's notes/crdt.md section on snapshots of paged states: the key is part of every write's value inside the entry, so the rule stays). A page walk must gather those writes from every stored collection under that dot into one output, a multi-source merge (the branch's snap_walk module, about 470 lines; +1,400 lines in all).
- The merge's memory is bounded for honest states (each entry has its own dot: at most about 2^depth sources) but not for hostile ones: readers never check that a dot names one key, so a forged state with N keys on one dot opens N sources at once (an ignored failing test on the branch, one_dot_many_keys_memory: 3 KB held at 4 keys, 41 KB at 64).
- A dot may name several keys in a state reached from valid blobs (notes/crdt.md, the records of a dot), so no decode rule bounds the source count: resuming needs a per-source cursor (re-reading below a cut), a re-read cost in the hostile case only. Weigh whether the whole page walk is worth its size against the priority of this issue.

