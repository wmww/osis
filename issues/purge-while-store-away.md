# A purge made while a store keeping S unread is away is never deleted there
> Summary: a body purged while the store source is disconnected stays at that store after it rejoins (admin or writer purger alike); only its expiry removes it.
> Priority: normal
> Tags: sync, read

Repro (osis-sync World, `deletes::setup`): node 2 writes `u:v.0` (`AuthorOrAdmin`), `run`; `power_off(1)` (the node keeping S unread); node 0 (admin, delete key) or node 2 purges the commit, `run`; `power_on(1)`, `run`, `advance(MAX_DRIFT_MS + 60_000)`, `run`: node 1 still holds every entry of the commit. With node 1 connected during the purge the entry goes at once (`deletes::a_writers_purge_of_its_own_write_deletes_it_at_a_node_keeping_s_unread_spec_sync_ids_6`).

Likely cause (unconfirmed): once the purged body's judgement goes idle (`judged.unwant`, verdict removed) nothing judges it again when the source rejoins: the rejoining stream shows nothing new for it (its `seen_added` is unchanged), and a writer's store source joining judges only what its stream shows. spec/sync-judgement.md §3 (Deletes, Dropped bodies: a dropped body's entries stay known) needs the deletes owed at a source to survive its absence.

Fix with a World test: the repro above (admin and writer purger), plus a writer restart while away, which exercises the kept `bp/` salt and aspects (`BlobOf`).
