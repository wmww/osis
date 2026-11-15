# fathom-rebuild-review-9
- `wt claim` refused: free wt2 held uncommitted changes (a roles-model dev-dep on osis-engine, an untracked rotation/tests_forks.rs) on `fork-sides`, released without committing. Saved as local branch `fork-sides-wt2-leftover` (two wip commits), then claimed.
- The brief's sha for item 3 (7029e1497) never existed on origin; the branch tip moved during the review (fetch again before reading).
- Deleting a dead `pub fn` trips tools/policy.py when tools/dead_pub_allow.txt defers it for the sync rebuild: read that line first.
