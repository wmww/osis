# keel-floor-join
- A regex adding a struct field before `floor` in every `Edge { .. }` literal also hit `ct::Edge { floor, ..edge(..) }`, overriding the spread with `retain: false`: check every inserted field for a later `..base`.
- `ct::Edge` <-> `osis_perm::Edge` is converted in four places (`flows::edges::perm_edge`, `validity::edge_of`, `read.rs`, the index's `Rec`), so a new edge field silently reads false at receivers until all four carry it; the engine test caught it, nothing at compile time did.
- Engine and held-model builds from this worktree take 5-8 min cold; every first `cargo test` moved to the background.
