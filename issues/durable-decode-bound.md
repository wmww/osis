# Durable deltas decode with no memory bound
> Summary: Tess's decision B (per-blob item cap `MAX_PAGE_ITEMS`, then verify and join page by page) is built through step 5: a 10^6-key map's commit or snapshot applies in 0.23-0.35 GB. Left: the writer holds the delta whole (2.2 GB, the op API), its snapshot loads, clones and copy-indexes the whole state (2.3 GB), `covered` holds the body and the snapshot's part at it (3.5 GB), and step 6 (root tables paged, a format change).
> Priority: low
> Tags: security, crdt, engine

The steps cited from code: 1-2 streaming re-encode and piece iterator (osis-crdt `stream.rs`, notes/crdt.md Wire), 3 engine apply per piece (notes/engine-paged.md Streamed apply), 4 streamed readers of held parts (Streamed readers), 5 encoder pages as elements come (`codec::Pager`). Target: memory about one decoded page plus the state pages touched, the store transaction's 16 MiB spill buffer, and a few bytes per element of tracking.

## Left whole at the writer (10^6 keys)
  - The delta: the op API takes whole `Value`s (`Mutation::set`) and `Batch` resolves the ops into one fragment, so the writer holds the input value (about 0.4 GB with the step's clone) and the delta (`approx_bytes` 1.9 GB: about 1.9 KB per entry of an int key and int value, a representation cost of `Map`'s records and key index). That is the 2.2 GB of the write.
  - The writer's snapshot (`snapshot_if`): loads and clones the whole state (+1.9 GB) and encodes it (now about one page). Its local apply joins it a piece at a time (a valid snapshot's copies are never compared with the state). Encoding from the paged state a page at a time (the encoder pulling each paged position's state pages, twice for the collecting pass; expiring values stripped and `own_retentions` read per page) would save the load and clone: the page-pulling encoder (the `Track` path walk the check already has, plus an engine page source over `PageIndex` in wire order).
  - Related: rewriting every value of a big paged map is superlinear in the ops (issues/big-map-rewrite-cost.md).
- `covered`: the body, with the snapshot's part at the body's positions accumulated (3.5 GB, 85 s; `Fragment::part_at`). Page by page on both sides needs a pull decoder walking the two streams side by side, or tracking which body positions some snapshot page reached: subtle.
- Role-class bodies stay whole (rosters of thousands, not millions). Not streamed: paged positions inside a `Slots` slot, a sequence element's content or a page; paged sequences at apply; a reset over nested paged collections.

## Measured (`memory::big_map_apply_memory`, release, in-memory stores, 10^6 keys)
Commit / snapshot with pages 21 / 22 MB. Write 2.2 GB, 135 s (snapshot 2.3 GB, 277 s); a node holding the thing applies 0.23 GB, 276 s; a node applies the snapshot alone 0.35 GB, 224 s; about 0.23-0.26 GB of each is what the store keeps. Box at load 25-60, so times only roughly comparable.

## Step 6
6. **Root tables page** (format change, about 300 lines plus spec): `Sources`, `Commits`, `Absorbed` and `Frontiers` may be `[Link+]` like element arrays, decoded first and held as compact tables (about 50 B per entry: 10^6 commits about 50 MB). Needed before snapshots of aspects written by more than about 10^6 session-form or 8 x 10^4 commit-form commits.

- **Snapshot root tables**: they do not always fit. Measured per absorbed commit with surviving stamps: session form 8 B and 4 items (`Commits` entry), so about 10^6 commits fill `MAX_BLOB`; commit form (role commits, multi-node key actors) 107 B (`Sources` 33, `Absorbed` 54, `Commits` 6) and 12 items, about 78 000 commits. An aspect past that cannot be snapshotted (the builder refuses a delta over `MAX_BLOB`). `MAX_PAGE_ITEMS` does not count these tables (bounded by `MAX_BLOB`, decoded into small records).

## Store transaction memory
- **Store transaction memory**: bounded already. The osis pager keeps a transaction's dirty units and blobs in memory up to `StoreConfig::spill_bytes` (16 MiB), then writes them early as journal rows (each spill one backend commit); only about 48 B per unit written stays. Under the file backend each backend commit is one redb write transaction; redb 2.6 keeps its dirty pages in a write buffer capped at a tenth of its cache (default cache 1 GiB, so about 100 MiB) and writes the rest to the file before commit. Aside: osis opens redb with the default 1 GiB cache, 90% of it a read cache that a large store fills (resident memory); worth a config decision.
