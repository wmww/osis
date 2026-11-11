# A purge re-snapshot refused for want of delete keys is lost
> Summary: node-sync's `purge_resnapshots` (sync/pass/delete.rs) takes the aspects a purge request named (`Engine::take_purges`) and calls `Engine::snapshot` once; a writer whose delete keys of the thing are not here yet (`write::MayWrite::Later`) is refused and the aspect is gone from the list, so it never writes the re-snapshot once the keys come: whether it repairs (spec/commits.md §5 Purge) depends on arrival order. Readers also call it and log a Permission diagnostic per purge. Safe side (the purger re-snapshots too), but the same shape as the purge-on-replace cover's wait.
> Priority: low
> Tags: retention, node-sync

## Direction
Ask `may_snapshot` first: `No` skips silently, `Later` keeps the aspect owed (in the engine, beside `Indexes::cover_waits`, woken by `replace::wake_covers`'s journal read) rather than in a list node-sync drains once.
