# walk-purge-review
> Summary: Workflow snags met reviewing the walk's purges.

- `tools/claim` hit the worker's still-running `wt release` (several minutes pruning); waited on its PID with `tail --pid` in the background plus `claudewait`, which beats re-polling `wt list`.
- Reproducing a dump comparison against the pre-branch build needs the column-split dump back-ported to the base commit by hand (its `reading()` and `Changed` differ): a temporary branch in the same worktree, rebuilt twice.
