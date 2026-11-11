# test-setup-copies
- `tools/bin-at` checks REV out in the worktree for its whole build: no edits meanwhile, and the next build recompiles everything REV touched.
- Wall times of the same test module moved 60 s to 150 s between runs at load 30; only `tools/icount` gave usable comparisons.
