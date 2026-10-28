# osis-crdt cleanup left over
> Summary: Duplication and loose ends in core/crdt/src a simplify pass found and did not fix: two path walkers that disagree on map keys and enum cases, the diff/edit step appliers, several read-only stamp walks, set-element vs map-entry join, repeated "record holding a dot" checks, register clones on `Slots` reads, test-only public API.
> Tags: crdt

Behaviour-preserving unless noted; none is a known bug.

- **Two path walkers.** `UndoBuffer for Fragment::before` (undo.rs) and `Fragment::at` (access.rs) walk the same `PathSeg`s but differ: at a map key `before` takes the lowest live entry, `at` the join of the live entries (what the key reads as, §5.6); at a `Case` `before` does not check the case is current. `undo_at` restarts the path at every map entry (`Sub`), so `before` never sees a `Key` from this crate; pick one semantics (probably `at`'s) and merge.
- **`seq_diff::diff` and `seq_diff::edit`** repeat the step application for text and list (flags for `Del`, nested writes for `Pair`, `insert_runs`), differing only in how an old index finds its current element and anchor. One applier taking those two lookups would halve them.
- **Read-only stamp walks.** `remap.rs` `Writes` and `Any`, lifecycle `dots_in`, `strip_values`, `remove_dots_in`, `map_dots` each spell out every encoding's stamps. A generic visitor over (stamp, role) could drive at least the read-only ones; mind `Any`'s early exit and no expansion of range records.
- **Set element vs map entry join** (state.rs `join_elems` / `join_entry`, `prune_elem` / `prune_entry`): the same reset, raise-prune and content join, the entry adding key and creation. Similarly `batch::overlay` for maps repeats `overlay_elems`.
- **"Record holding a dot"** is re-implemented in `Shown::find`/`find_mut` (shape.rs), `Graph::lookup_near` (linearize.rs), `Lin::holder`, `seq_span::overlaps` and `split_plain`, beside `seq_span::find`.
- **`batch::resolve`** creates a new map entry by hand (fresh dot, creation stamp) instead of `ops::new_entry`, because its content may be `None`.
- **Tombstone literals** `Entry { reset: Some(r), key: None, frag: None, created: None }` and `Elem { reset: Some(r), frag: None }` repeat across ops.rs and undo.rs.
- **Hot path**: `MemberRef::with` wraps a register slot in a cloned `Fragment` per call; `chosen_member` on a `Slots` position calls it per member, and `present`/`inner_any`/`inner_max` of `Slots` do too. A register-aware `all_max`/`present` would avoid the clones.
- **`seq_lin`**: `Lin::same` is `PartialEq for Lin` without chars; `Partial::take` copies `Missed` field by field.
- **Public API used only by this crate's tests**: `Received::add_frontiers`, `SeqPlace::same`/`order`, `Lin::same`; `touched_elems`, `Interner::intern`, `Enc::{dot_order, is_own, opt_stamp}` are public but used only inside the crate. `cut_dots` has no caller outside tests yet (a client API for cut/paste).
