# review-redeem
- The redeem arm's `flat_work` skip sat in shared `grants_as_fresh`, behind an ignored test: invisible to the gate, but a fold into the default test would have carried it. Checks guarded by an arm flag deserve a grep in review.
- Gate build stage 4.4x over its CPU limit (553 s, load 6): a claimed worktree warm from another base still rebuilds engine and its dependents.
- The gate's one NEW (sync differential stale read, no link in its script) failed on main too: a property seed new to main cost a `bin-at` build and a spare-worktree landing before this branch could land.
