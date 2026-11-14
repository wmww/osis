# A purge re-snapshot owed is lost on a refusal or a crash
> Summary: `Engine::purge_resnapshots` (retention/snapshot.rs) drains the aspects purge requests named (`Changed::purges`, in memory) and calls `Engine::snapshot` once each. A writer whose delete keys of the thing are not here yet (`write::MayWrite::Later`) is refused and the aspect leaves the list, so it never writes the re-snapshot once the keys come; a node that stops between the purge's transaction and node-sync's next `engine_events` loses the whole list (nothing rebuilds it at start). Either way whether it repairs (spec/commits.md §5 Purge) depends on arrival order or timing: nodes that missed the purged part read what it replaced until another writer re-snapshots or compacts. Safe side when other writers held the part (they re-snapshot too), but the purger alone may have held it.
> Priority: low
> Tags: retention, node-sync

## Direction
Keep the owed aspects in the engine, durable and written in the purge's transaction (beside `Indexes::cover_waits`), cleared by the snapshot: `may_snapshot` first, `No` drops the entry, `Later` keeps it owed, woken by `replace::wake_covers`'s journal read; at start every owed aspect is tried again.
