# A deleted shared ephemeral thing comes back
> Summary: `delete(T)` of a synced ephemeral thing frees it at the deleter and sends only the removal from its groups, so holders keep reading the old values, and those return to the deleter later. Breaks "if something is deleted it stays deleted"; a one-line fix in `freeable` is tried and works.
> Tags: ephemeral, engine, tess-call

Test `ephemeral::deleted_thing_stays_deleted_at_holders_spec_sync_9`. `freeable` frees T, so its resets are unindexed unsent. The holder reads the old value until it restarts. Its next write reaches the deleter (kept rows). Past the host's tombstone (`MAX_DRIFT`) its reconnect uploads the old entries and the deleter reads them again.

Fix tried: `freeable`'s `synced` also holds when `core.memory.kept.contains_key(t)`: a thing a commit was kept on under a label is not freed at once, so the usual resets go, as for the undo of a creation. A thing never kept under a label is still freed at once. The test then passes (a holder's later write still shows, alone: as a durable delete, a later write wins over it). Oracles with it on fresh seeds: reverts 500, churn 100, window 100, sim `ephemeral`, `ephemeral_capped` 10: alike; restarts as without it. Two tests free a synced thing and need rewriting: `freed_thing_received_again_keeps_counters_spec_crdt_2_1`, `kept_row_goes_with_the_thing_spec_sync_9`.

Cost: the deleter keeps the record and one reset commit per deleted shared thing until restart (own: not capped). Holders hold that reset instead of today's whole copy, under the label cap.
