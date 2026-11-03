# app-rejoin
- Tier 1 + both clippy runs + app build took 17 min at load 45: tier 1 rebuilt osis-crdt and up after earlier `-p osis-chat`/`-p osis-cli` runs (the `-p` dev loop did not share the workspace's artifacts for those crates here).
- No `chat ls` in the CLI: finding a chat's tid on a store after a `chat create` that exited 6 (hosts unreachable, done locally) needs `status`.
- A failed join in the app shows only in the small footer status line, easy to miss: likely why "nothing visible" was reported.
- Review: the kit fix-disabled check rebuilt the GUI workspace for 4 min; chained `claudewait a || claudewait a` ran into the 180 s move (call it once per Bash call).
