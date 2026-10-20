# The node rewrites a whole aspect state on every edit
> Summary: The engine keeps each aspect's state as one encoded unit (`Tx::set_state` re-encodes the whole `Fragment`), so one entry edit of a 10^6-key map writes about 95 MB to the store and takes about 9 s; spec/requirements.md (Scale: O(change) per edit) is missed at the node. The store's paged tables and the crdt's paged snapshots are O(change) already; the engine does not use them.
> Tags: performance, node, storage, crdt

Measured (`cargo test --release -p osis-node --test scale big_map_edit_cost -- --ignored --nocapture`, shared 4-core box): one `PathOp` set into an untyped map aspect.

| keys | fill commit | edit time | store bytes per edit | commit bytes |
|---|---|---|---|---|
| 10^4 | 0.16 s | 71 ms | 367 KB | 299 B |
| 10^5 | 1.0 s | 0.84 s | 4.0 MB | 303 B |
| 10^6 | 17 s | 8.6 s | 94.6 MB (3 batches, spilled) | 307 B |

The commit itself is O(change) (about 300 B); the local cost is the whole state re-encoded and re-encrypted (about 40 B per key per write at 10^5, more once spilled) plus the in-memory state cloned per path op (notes/crdt.md: "ops scan entries and clone the joined map per path op").

Fix shape (notes/local-store.md, Units: "a large state is paged like a snapshot ... MVP requirement"): store a state above `PAGE_TARGET` as osis-store table pages (`create_table`/`table_*`: one shredded edit of a 10^6-entry table writes 3 unit rows, about 36 KB, osis-store `paged.rs` `million_keys`), keyed by map key / dot, and load only the pages an op or a join touches. Snapshot encoding is already incremental in bytes (one new page per change at 10^6 keys, osis-bench `scale.rs`) but still re-encodes the whole state (1.2 s at 10^6).
