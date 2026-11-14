# A purged thing's sync ID is never left
> Summary: A purge request with no `expires` keeps the destroyed thing's own sync ID S, its request entries and the thing's secrets at every holder forever, by spec; the alternative is the requests leaving at the end of their window.
> Priority: normal
> Tags: sync, engine, tess-call

spec/sync-judgement.md §5 keeps the destroying requests under an emptied S until their expiry; a purge request without `expires` has none, so every node holding t's secrets keeps syncing S, keeps the secrets (for the head's delete key) and never forgets S; stores keep the request entry, and a node keeping S unread is never sent the closing step (it goes once its stream shows no entry, spec/sync-judgement.md §6 Closes). That is how a node away past the window still learns of the purge, so it may be intended; the alternative is the requests leaving at the end of their window (`wall_ms(ts) + ROLE_KEEP` or `expires`, the earlier) and accepting that a node away that long never learns (as for releases, spec/sync-judgement.md §5 Limit). Tess's call.

Test once decided: core/sync/tests/it/destruction.rs `a_destroyed_things_sync_id_empties_but_its_request_past_its_window_spec_sync_judgement_5` asserts today's reading (the request stays at node 1).
