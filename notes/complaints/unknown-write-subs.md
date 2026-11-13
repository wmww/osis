# unknown-write-subs
> Summary: workflow notes from fixing subscribers that missed a commit found landed after a failed sync.

- `wt claim` printed the worktree path but exited 1, and the session's primary directory pointed at a different worktree (wt9) than the one claimed (wt12): easy to build in the wrong tree.
- osis integration tests cannot reach `osis_store` (not a dev-dep), so a fault-injecting store needs a hidden `internals` hook plus a `tools/dead_pub_allow.txt` line.
