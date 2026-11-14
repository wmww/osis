# A purge by commit fails once the commit was forgotten
> Summary: `Purge::Commit(id)` answers "unknown commit" once a snapshot covered the write and node-sync forgot its commit (spec/commits.md §5 Forgetting), though its values live on as the snapshot's copies, which a purge request naming it would hold value-less (§5 Covered Limit). Automatic compaction makes this a race for any write on an aspect with no history.
> Priority: normal
> Tags: engine, api, tess-call

Seen in osis `sharing::purge_without_the_right_is_refused_spec_permissions_6` and `watch::path_listener_hears_an_expiry_and_a_purge` (both now keep history or purge first to stay clear of it). A purge item names a write by `ts` and source, which the snapshot's copies still carry: the engine could resolve a forgotten commit's item from them, or the API could say the commit is gone (and point to `Purge::Author`/`All`). **Tess question:** should purging a write by its ID keep working after compaction forgot the commit?
