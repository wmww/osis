# decoded-recheck-cost
> Summary: plant runs against the old code meant swapping `core/engine/src` from an older commit into the worktree for each build (no stash, one target dir), so the worktree could not be edited while they ran (about 18 min for 8 plants).

- `claudewait A; claudewait A` in one Bash call passes the tool's 120 s timeout and gets moved to the background: one wait per call.
