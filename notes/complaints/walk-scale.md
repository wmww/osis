# walk-scale
> Summary: Workflow snags met while building components, forget and the void-check cache in osis-perm `paths`.

- `tools/mutate.py` with five mutations in one call reported "none" for the fifth (`!it.shape_well || !dead.is_empty()` -> `!it.shape_well`, mutant-4's log missing from its run dir, only mutant-0..3 written) though the same plant by hand fails `counts::a_path_joins_components_only_through_held_edges`. A row of "none" with no log is worth a recheck by hand.
- `mutate.py` refuses an OLD that occurs twice; `self.find(a)` matched inside `union` too: give the whole statement.
- A `git commit -qam wip && <edit> && cargo ...` chain stopped silently at "nothing to commit" (build.md Footguns says so; met anyway).
