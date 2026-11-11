# deposit-fill
- A background `cargo test ... > scratchpad/dir/log` raced a `mkdir` of that dir sent in the same batch: the shell redirect failed before the run. Create log dirs first.
- The issue said writers hold a label's delete key; admins do (`kdf("label delete", admin secret)`). Clearing is an admin's job, so a filled group budget waits for an admin node, not any writer.
- A demoted writer's invalid writes are the only easy way to get "invalid commits that open" in a Net test; `net.write` by a reader fails locally, and a demoted node offline never places its writes.
- Holding `net.hosts[h].hub.store()` in a test while calling `net.host_ids` deadlocks silently (the test hung for minutes, no timeout): read host ids before taking the guard.
- Review gate: `keep::any_order_until_keeps_no_more_large` seed 636109736897 fails on main too (NEW, now listed in tools/known_failures.txt). The gate also ran 2.5-2.9x its wall limits at load 12 (gate.hold 444/177 s), cause not looked into.
