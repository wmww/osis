# eph-replay
> Summary: footguns met while fixing ephemeral replay, presence pin and forged cover.

- Net tests: `set_online(n, true)` + `run()` does not reconnect at once; a node needs `advance` (tens of seconds) to redial before it syncs again.
- Sabotage-checking new tests needs care: an existing early path (presence drop when no server holds an entry, list-based drops needing `/created` listed too) can make a test pass without the fix; check each new test fails with its fix disabled.
- Reviewer: gate took 301 s at load ~8-15 (doc says ~90-150 s warm); editing a source file while the gate runs leaves it unclear which tree it checked: re-gate.
