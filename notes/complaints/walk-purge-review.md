# walk-purge-review
> Summary: Workflow snags met reviewing the walk's purges.

- `tools/claim` hit the worker's still-running `wt release` (several minutes pruning); waited on its PID with `tail --pid` in the background plus `claudewait`, which beats re-polling `wt list`.
- Reproducing a dump comparison against the pre-branch build needs the column-split dump back-ported to the base commit by hand (its `reading()` and `Changed` differ): a temporary branch in the same worktree, rebuilt twice.
- The gate selected nearly every property (a perm change reaches most crates) and ran 9,028 CPU-s at load 51, 2.2x its cap; two failures on main (a content-world disagreement from the sibling-drop rule, a custody `writes` check) needed bin-at reruns to mark KNOWN.
