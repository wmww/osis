# self-removal-crash
- `wt claim` printed wt1 while the session's environment said wt2; easy to work in the wrong tree.
- `git checkout main -- <src>` for a fix-disabled probe pulled in other branches' newer main code (compile errors); use `HEAD~1` / the merge base.
- Grepping `core/node/src/sync/*.rs` misses `sync/pass/`; I nearly deleted the `first` field as dead. Use `-r`.
- (review) `wt claim` run twice in one shell line: the second call printed nothing usable and `cd $(...)` landed in `.worktrees/`. Claim once, then cd to the printed path.
- (review) Races between a pass's upload and download hide in the net harness (upload usually wins); a host policy refusing uploads (`cap_entries: 0` via `restart_host_with`) forces the other order.
- (review) Coordinator asked to rebase while my gate was building; stopping it mid-build left `undefined hidden symbol` link errors (osis-crdt, osis-label) on the next gate: notes/build.md's fix (delete `target/debug/incremental/<crate>-*`, even all of it) did not help: the stale rlibs in `deps/` stayed; `cargo clean -p <every workspace crate>` fixed it, costing two failed gates and a 933 s cold gate. Never stop a gate mid-build; let it finish, then rebase and re-gate. Also local `main` lagged `origin/main`: rebase onto `origin/main` after `git fetch` when told main moved.
