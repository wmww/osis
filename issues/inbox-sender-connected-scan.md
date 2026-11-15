# Each inbox blob taken rebuilds the sync set and walks every record chain
> Summary: `Engine::author_connected` (core/engine/src/sync/inbox.rs, spec/sync-inbox.md §2 Taking) calls `sync_set_now` (unmemoized: `thing_sync` per synced thing) and walks every synced thing's record chain, then asks `role_now` of each, for every inbox blob it judges: O(things synced × chain depth) per blob, O(blobs × things) for a burst of deposits or invites.
> Priority: low
> Tags: engine, sync, performance

Fix: read the memoized `sync_set` and keep the connected things (the sync set's things and their record chains) as one memo value; then answer from the author's own roles (the things it holds a role on) intersected with it. Count test: one inbox blob taken at 10 and 100 synced things costs the same.
