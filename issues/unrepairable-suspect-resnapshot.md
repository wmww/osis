# A writer re-snapshots an unrepairable suspect aspect at every heartbeat
> Summary: A pending-expiry flag never goes dormant, so a reader keeps listing the aspect. When no snapshot can make the reader's state match (order seed 5288), every writer with a different digest writes a new snapshot at each new heartbeat commit of that reader (6 h), for as long as the aspect stays in its newest `MAX_HEARTBEAT_SUSPECTS`.
> Tags: node-sync, engine, growth

`SyncEngine::repair_suspects` keys `repaired` by (heartbeat commit, thing, aspect), in memory, and calls `Engine::snapshot` whenever its digest differs. Seed 5288: the reader dropped a part at T; a node that applied it un-merges an entry whole because of the part's residue, and the reader keeps that entry from another snapshot's copy. No snapshot changes that, so the digests never agree. Each 6 h heartbeat then costs each writer a full snapshot commit of the aspect. That is up to 32 aspects per reader, per writer, 4 times a day. Before seed-5288 the flag went dormant and nothing was listed: silent, no churn.

Possible rule: skip the re-snapshot when this writer's newest held snapshot of the aspect was taken from the state it holds now, since another one repairs nothing more. Check that a lost or invalid snapshot still gets re-sent.
