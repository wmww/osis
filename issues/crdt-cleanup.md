# osis-crdt cleanup left over
> Summary: Near-parallel code in core/crdt/src judged not worth merging: set-element vs map-entry join and overlay, the mutating stamp walks. Revisit only if one of them grows.
> Tags: crdt

Behaviour-preserving; none is a known bug.

- **Set element vs map entry** (state.rs `join_elems` / `join_entry`, `prune_elem` / `prune_entry`; batch.rs `overlay_elems` vs the map arm of `overlay`): the same reset, raise-prune and content join, the entry adding key and creation. A shared `Rec` trait came out line-neutral: the entry's creation prune sits between the content prune and the content join, and `Changes` deaths are ordered, so the hooks cannot collapse. The overlay pair shares about three lines.
- **Mutating stamp walks** (`map_dots`, `strip_values`, `remove_dots_in`): each changes different parts per encoding (`Slots` rebuilt by join, map keys, sequence records expanded); the read-only walks share `remap::walk`.
