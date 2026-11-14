# Invalid bodies at sources are never deleted
> Summary: no node deletes a blob at its sources for holding a delta it judges invalid (spec/permissions.md §6, spec/sync-judgement.md §2: they are the refetch source when it turns valid), so junk a member logs under a sync ID that is never valid (a reader's or ex-writer's writes, a non-admin's `retention^.0`) stays until its expiry, a purge, or its thing leaving the sync ID's closure, covered by a snapshot or not (a cover drop of a part judged invalid is an invalid drop), filling the per-sync-ID caps of nodes keeping it unread. Bounded by that cap, not by anything a right holder can do.
> Priority: low
> Tags: sync, security, retention

Options: a right holder deletes invalid bodies at its sources (then a re-grant restores only what an author or another node still holds, as for a body no holder has), maybe only bodies never valid at any key a removal could reopen; or accept, stated. The author keeps its own invalid bodies either way and logs them again (must-hold), so deleting the author's copy while it lives is a delete/re-log loop to avoid.
