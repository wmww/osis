# eph-restart-loop
- `tools/bin-at` needs a clean tree and checks out other revisions in the worktree: any file edit while it builds lands on the wrong revision. Park edits in a diff in the scratchpad first.
- `Engine::me()` panics on hosts' sync engines: a probe in shared node-sync code must use `account_tid()`.
- `Net::set_online(n, true)` reconnects only at a retry tick, so a test needing "no time passes" (a relay delay still pending) cannot take a node offline; `held_to` + `release` keeps the connection and holds the bytes instead.
