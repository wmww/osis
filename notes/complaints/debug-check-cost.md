# debug-check-cost
- The session's primary working directory was another branch's worktree (wt14, test-setup-copies) while `wt claim` handed out wt15: easy to edit or build the wrong tree. Every command here names wt15 explicitly.
- `tools/bin-at` checks out an old revision in the worktree; a copied test binary still running reads the checked-out fixtures, so old-vs-new runs and an `icount` of a copied binary cannot overlap.
- A hasher keyed on a candidate's first 8 bytes made the harvest slower, not faster: many random-looking windows share a structural prefix. Fold every word.
