# cover-rule
- The brief named `Departure::since` as on main; it was only on the unmerged `raise-followup` branch. Started the branch from it (fast-forward).
- TLC raised "apply function to an argument not in its domain" from `a = "O" \/ f[a] = ADMIN` inside an operator reached through a set filter: the disjunction was not short-circuited there. `IF ... THEN TRUE ELSE f[a]` works.
- Checking a new test against the old rule meant checking out the old revision in the task worktree (a wip commit, a branch, a rebuild each way, about 3 min); it cannot overlap a TLC run reading the worktree's model files. `tools/bin-at` has the same constraint.
- Waited 16 min for the heavy lock before the first TLC run.
