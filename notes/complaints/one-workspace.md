# one-workspace
> Summary: Footguns met merging the GUI into the root workspace.

- Box at load 25-75 throughout: the warm-up of a stale worktree took 18 min, an osis-base manifest change (the pins) rebuilt core in 16 min (3720 CPU-s). Numbers in the report are CPU-s; wall says little.
- `/usr/bin/time ... 2>&1 | grep -c` swallows time's own output: write it with `-o FILE`.
- `cargo tree` diffs (bare vs `--workspace` vs `-p X`) find feature leaks in seconds without building; the build-based unification check then confirms.
