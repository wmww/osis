# relink-order complaints
> Summary: workflow notes from the relink-order task.

- `net.read` on a large register returns the root `Link`, not the string: a test comparing it to the written value fails confusingly; compare `is_some()` or use `get_full`.
- Review: checking that a new test fails without the fix took `git checkout origin/main -- core/node/src` in the worktree, then back; no stash, and cheap with a warm target.
