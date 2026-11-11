# Invalid bodies at hosts are never deleted
> Summary: no node deletes a blob at hosts for holding a delta it judges invalid (spec/permissions.md §6, spec/sync.md §6: hosts are the refetch source when it turns valid), so junk a label member uploads that is never valid (a reader's or ex-writer's writes, a non-admin's `required^.0`) stays until its expiry, a purge, or its thing leaving the label, filling the host's per-label cap. Bounded by that cap, not by anything a right holder can do.
> Priority: low
> Tags: sync, security, retention

Options: a right holder deletes invalid bodies at hosts (then a re-grant restores only what an author or another node still holds, as for a body no holder has), maybe only bodies never valid at any key a removal could reopen; or accept, stated. The author keeps its own invalid bodies either way and re-uploads them (must-hold), so deleting the author's copy at hosts while it lives is a delete/re-upload loop to avoid.
