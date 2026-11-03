# labels-cost-review
- A foreground build plus test run in one Bash call moved to the background at 180 s three times; the pipe to `tail` then showed nothing. Build, copy the binary, then run with `run_in_background`.
- `tools/bin-at` in a script bisected 187 commits in 8 builds, 11 minutes, but holds the worktree: no edits meanwhile, read from the main checkout.
- `work_sets_match_full_passes` was exact only by luck once passes differ: under faults one message less rolls other dice. It failed on `grant_to_group` seed 71006 as handed over.
- `ls -t` on the shared tasks dir picked another agent's task for `claudewait` once, as coordination.md warns. A script gives the ID.
