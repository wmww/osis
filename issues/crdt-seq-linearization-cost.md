# Sequence ops in a batch and bulk changes still cost a whole-state pass
> Summary: Sequence reads, index lookups and typing joins now use a cached placement (`seq_lin`), but a batch's second and later ops still copy the whole state, any move/reset/concurrent-older insert rebuilds the cache from scratch, and splicing is O(n) per joined delta.
> Tags: performance, crdt

Repro: `cargo test --release -p osis-crdt --lib -- --ignored budget_big_text_spec_6 --nocapture` prints the times.

Done (`crates/osis-crdt/src/seq_lin.rs`, notes/crdt.md Linearization):
- `Seq` keeps a placement cache (order, parents, spans, visible list, waiting anchors), built by one `place_idx` pass, followed through joins that add elements (runs spliced after their anchor when they beat its first child) or change flags/content; every other change of `elems` drops it (`elems_mut`). Tested equal to a whole pass after every join in the lockstep differential tests and `cached_placement_follows_typing_spec_6`.
- `visible`, `read`, `element_at`, Delete/Move/Paste use the cache; `present_slot` and `cut_dots` no longer clone the state; `joined` no longer prunes (and so drops the cache) without a reset from above.
- Text sessions already emit one `Op::Edit` per commit (osis `text.rs`).
- Measured (release, 4 cores at load ~20, so only relative): build of 10^5 chars in 1000 commits 194 s → 24 s; one op 273 → 97 ms; two-op batch 763 → 354 ms; read 322 → 185 ms; small join 6.6 → 275 µs (O(n) splice instead of O(1); was followed by a full place on next read). Re-measure on an idle box.

Remains:
- Batch clone: a batch's later ops resolve against `joined(state, acc)`, a full copy of the state (plus a copy of the cache on its first follow). Keep the joined view in `Batch` and update it per op instead.
- Splicing and flag flips are O(n) scans and `Vec` inserts per delta; an order-statistic structure (blocked list with counts) would make index → dot and dot → position O(log n) / O(√n).
- Fallbacks to a whole pass: moves (position writes on existing elements), resets, range-record splits, an older concurrent insert landing below newer siblings, `Derived` dots, more than 32 anchor runs in one delta. Incremental re-placing of touched subtrees (and SCC recompute on cycles) is not built.
- `read` does one `BTreeMap` lookup per visible element.
- The measurement above predates the last change (first-child stamp computed on demand instead of a per-node `kid_max` map, which made each cache copy cheaper); not re-measured.
