# sync-audit
- Making two writers place separate encryptions of one body took three tries: writers wait `relay_delay` (up to `SETTLE_MS`) before uploading another's commit, and a reconnect races, so only `held_to` plus an advance past the relay wait gets both encryptions up.
