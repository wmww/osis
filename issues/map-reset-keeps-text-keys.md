# A map reset leaves a text or list entry's key in snapshots
> Summary: `replace` or `remove_aspect` of a `map<k, text>` (or struct or list around text) leaves each old entry's keyed record holding bare anchors, which repeats the key, so a snapshot carries it. A removal does not (spec/crdt.md §4.2). The same records make the one lattice exception: a removal's reset dropped by a later map reset keeps or loses the anchors by arrival order. Reads are equal; `state_digest` and snapshot bytes are not, and the order oracles' exact state check flags it (about 1 in 40 `order::arrival_order_seq_compact_large_spec_crdt_5_7` seeds, e.g. 7410006).
> Tags: security, crdt, tests

The record has no creation, so it looks like a partial receipt: its creation may yet come, and a later insert anchored there would read hidden at a node that dropped the anchors. So the lattice cannot drop them.

Simplest rule to try: a sweep (spec/sync.md §7). A compacting writer commits a key-erased reset for each keyed record holding no creation and no write under a map reset; `prune_dot` then drops the anchors, and the record goes. Cost: one tombstone per old entry, after a `replace` of a map of texts. It makes the state strict only once swept.

The oracle's exact check: decide with Tess whether states are compared without anchors of creation-less records (`hidden_anchors_gone` in core/crdt/src/tests_life.rs) until then. spec/requirements.md Deterministic says state, and this is state.
