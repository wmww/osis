# session-wrapup
- Worktree targets are 15-29 GB (notes/build.md says 11-12 settled): `wt` reports "noatime: targets not pruned", so stale artifact generations pile up. Disk is fine (493 GB free); delete and rebuild an oversized target, or make wt prune without atime.
