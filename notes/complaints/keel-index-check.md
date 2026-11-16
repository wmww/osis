# keel-index-check
> Summary: Mishaps met while measuring the index check's cost.

- `wt claim keel-index-check origin/main` exited 1 yet printed a usable worktree path.
- Counting base and new properties back to back in one `tools/heavy` hold trips its limit (2x the work); expected, but the LIMIT line asks for a report.
- The engine properties at a fixed offset fail on main in three known ways (custody, held_set_decides_plain, unmerge_paged): counts compare only because both sides fail alike.
