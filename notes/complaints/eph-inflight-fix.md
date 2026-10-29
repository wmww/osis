# eph-inflight-fix
- The random-window failure prints only the step log; finding the culprit needed temporary eprintlns in the lane (who holds which entry, `present` per server) and a debug dump. A test-only lane dump (`SyncEngine` doc-hidden, entries/present/served_src per label) would have cut that to minutes; not added.
- The failing seed looked like in-flight coalescing (the brief's suspect) but the bug was older: a reconciliation's reply judged against the lane as it is at the reply, not the set it sent; the inflight variant's slow server is just what stretches a reconciliation over other traffic.
- `git reset --soft` off a wip commit left its test debug staged; `git checkout <path>` then restored the staged copy, not HEAD's. Use `git restore --staged --worktree`.
