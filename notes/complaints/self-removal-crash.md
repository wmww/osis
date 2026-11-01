# self-removal-crash
- `wt claim` printed wt1 while the session's environment said wt2; easy to work in the wrong tree.
- `git checkout main -- <src>` for a fix-disabled probe pulled in other branches' newer main code (compile errors); use `HEAD~1` / the merge base.
- Grepping `core/node/src/sync/*.rs` misses `sync/pass/`; I nearly deleted the `first` field as dead. Use `-r`.
- (review) `wt claim` run twice in one shell line: the second call printed nothing usable and `cd $(...)` landed in `.worktrees/`. Claim once, then cd to the printed path.
- (review) Races between a pass's upload and download hide in the net harness (upload usually wins); a host policy refusing uploads (`cap_entries: 0` via `restart_host_with`) forces the other order.
