# undo_target reads every kept part of a sequence
> Summary: One undo check reads each kept earlier part of the aspect back to the newest kept whole reset, so on a text or list with no resets it costs O(parts), about 2-3 body reads per part. Undo looks at only the delta's positions, but nothing says which parts touch a position. Bounding it needs that index, or a different rule for what an undo needs.
> Priority: normal
> Tags: engine, kit, osis

The about chip calls `undo_target` on every page refresh, and a per-generation cache misses since every commit steps the generation.

Counted by `undo::tests::check_cost_scales` (commit bodies read by one check, 400 commits to the field): written whole and kept until a date 3 (flat); written whole and kept for a while after replaced 408; typing 799; typing ending in a delete 1198.

Where the reads go:
- `kept_before` joins every kept part: only a kept whole reset ends the walk. Sequence edits carry no reset, and `seq_ops::undo` consults the pre-state only at the delta's dots, but a dot's earlier flag writes are in arbitrary parts and no index names them.
- `replaced_kept` walks every part before a restoring write: spec/commits.md §7 counts any part it may have replaced, and a write does not record what it overwrote.
- `kept` on a part replaced under a relative keep reads the aspect's held bodies once per transaction (`read_held_writes`, for `replaced_at`).

Ways out, each a design change: an index from a dot to the parts writing it (narrows `kept_before`; `replaced_kept` needs the same narrowing, a change to §7's "may have replaced"); a per-aspect summary of whether every earlier part is kept. Stopping early once the pre-state is "present" is wrong for nested positions: `undo_at` consults presence at each position of the delta, not just the root.
