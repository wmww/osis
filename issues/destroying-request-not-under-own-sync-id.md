# A request destroying a thing is never logged under the thing's own sync ID
> Summary: When an admin purges a thing's creation (or releases it), the request is logged only under the sync IDs of the groups holding the thing, never under the thing's home sync ID S, so another account reading or keeping S never learns of the destruction and keeps reading it.
> Priority: critical
> Tags: engine, sync

## Reproducers
osis-sync `destruction::repro_*` (ignored): node 0 makes t (filed in its D, home sync ID S), grants node 1's account sync and node 2's write, then purges t's creation (or `Engine::release`). Node 0 reads t destroyed; node 2 never holds the request and still reads t; past the window node 1 still holds S's entries.

## Cause
At node 0 the request's commit has a body under D's sync ID only (`Engine::sync_bodies`: `{D's S: copy}`). `sync_bodies_now` lists only sync IDs `thing_sync_now` reads, and t, destroyed in the request's own transaction, has no home sync ID any more (`home_sync_id(t)` is None). spec/commits.md §5 Destruction keeps the requests destroying t while a request is in force, and its sync IDs empty only once the destroying request is held there (spec/sync-judgement.md §2, core/test/tla/net/NetDestroy.tla): t's sync ID must stay read here, carrying its requests, until it keeps nothing. The facade's sync set (`set.rs`), and so `thing_sync`, must keep a destroyed thing's own sync ID while the thing keeps something.
