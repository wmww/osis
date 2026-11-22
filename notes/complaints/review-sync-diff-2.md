# Complaints: review-sync-diff-2
> Summary: A NEW failure found on main mid-review means a detour through main (detach, commit, push, rebase, hand-merge the issue file); the gate's selection and results go with its tmp dir, so the summary can't be re-read once the line is listed.

- The gate drew seed 61254442551, a differential class that fails on main too. Recording it on main first meant detaching the worktree to origin/main, committing there, then rebasing the branch with a conflict in the same issue file it rewrites. A `tools/known-on-main` helper (commit an issue line + known_failures line onto origin/main from any worktree) would save the switch and the rebuild it costs.
- The gate removes its `/tmp/tmp.*` selection and results at exit, so `tools/gate_failures.py` can't be run again to show the failure is now KNOWN after its line is added.
