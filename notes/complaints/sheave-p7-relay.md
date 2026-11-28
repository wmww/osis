# sheave-p7-relay
> Summary: Landing a first fix mid-task released the worktree and pruned its incremental build, so the second fix began with a cold 7.5-minute osis-sync build.

- `tools/merge-branch land` always runs `wt release` and prunes `target/` incremental sessions. A worker with a second fix to do must claim again and rebuild cold (7m30s for one osis-sync test). A `land --keep` that skips the release (or a brief saying "land each fix" noting the cost) would have saved it.
- The gate reported two ON-BASE failures (failing on main, no known line) that the worker had to replay without its own change to rule out before landing: about 7 minutes. Main gaining unlisted failures between lands lands that cost on whoever gates next.
