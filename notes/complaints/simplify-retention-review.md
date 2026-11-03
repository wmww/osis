# simplify-retention-review
- `tools/bin-at` leaves the tree at REV for the whole build: reading the worktree meanwhile silently shows main (a `wc -l` looked wrong); `git show branch:path` while it runs.
- `order::arrival_order_alike` failed on a fresh offset for a bug main has too (seed 8210052, issues/death-dated-early-733028.md): compare with `tools/bin-at` before suspecting the branch.
