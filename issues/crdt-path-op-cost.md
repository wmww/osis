# Path ops into large maps cost O(map)
> Summary: `Batch` resolves each path op by joining the state's position with the batch's writes (a clone) and finds a key's live dots by scanning entries; a put into a 10^5-entry map is O(map) per op. Add the local `key -> live dots` index (spec/crdt.md §5.6) and resolve along the path without cloning.
> Tags: crdt

Repro: no test yet: time one path op into a 10^5-entry map through `Batch` (osis-crdt).

- Where: `crates/osis-crdt/src/batch.rs` (`resolve`, `PathSeg::Key`, `PathSeg::Index`), `ops.rs` (`live_entries`, `diff` on maps).
- Join itself is fine (a one-entry delta into a 10^5 map: ~0.3 µs, `budget_big_map_spec_4_1`).
- The index is local, not part of the lattice: maintain it in `join_into`/`prune` of `Map`, or build it lazily per state and invalidate on join.
- Also: pages are fetched and joined whole (`codec::elem_items`); streaming join per page (spec/crdt.md §8) is not built.
