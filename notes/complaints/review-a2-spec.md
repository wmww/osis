# Complaints: review-a2-spec
> Summary: Workflow snags met reviewing and gating a2-spec.

- The gate waited about 10 minutes for the heavy lock before its held stages began; nothing says how long a hold ahead will last.
- A NEW sim failure that turned out to be on main cost a spare worktree, a 50 s rebuild there and a separate landing before the branch could land; the gate cannot tell main's failures from the branch's without that replay.
