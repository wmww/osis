# crdt-cleanup-2
> Summary: Workflow notes from the second line-cutting pass over osis-crdt.

- Shared helpers in seq_lin.rs (dot-map pointing, row depth, the plan checks) remove repetition but not lines: each helper costs what two call sites save. Lines there drop only from restructuring, not from folding idioms.
- `prune_page` and `Whole::add` look alike but go opposite ways (split a page into one-element pieces vs merge pieces into place): a shared split/merge pair costs as many lines as it saves; `Whole::add` by join would change what decode does (join prunes, needs canonical sides).
- The child walks in state.rs differ per walk in which records count, whether sets/bags or sequence content are entered, and early stop vs fold; only `has_any_reset`/`has_position_reset` fold cleanly into one.
