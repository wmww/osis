# sync-session complaints
> Summary: Footguns met building the sync session module.

- The worktree the environment named (wt9) was free and unclaimed; `wt claim` gave wt5. Agents may build in the wrong tree if they trust the environment's cwd.
- `osis-engine` `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` fails on the sync-rebuild base (5a3cca28d), unrelated to this branch.
- A background `cargo test ... > $scratch/x.log` into a scratch dir not yet made fails silently with exit 1 after a long wait: make the dir first.
