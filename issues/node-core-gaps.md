# Node-core gaps left after the engine core landed
> Summary: What osis-node's engine does approximately or not yet: imports from snapshot origins, element-level judging inside compaction snapshots, deaths of writes carried only by snapshots, chunk reuse and streaming of large values, O(history) open and re-judging, paged local state.
> Tags: node, permissions, storage

- **Import from snapshots** (spec/permissions.md §7): only ordinary commits are origins; writes held only in a compaction snapshot (their own body dropped) are not imported, and the schema table of import deltas is left empty (untyped).
- **Snapshots vouch for nothing** (spec/permissions.md §5.2): a snapshot body is joined whole; on rebuild the writes of sources with an invalid delta held here are removed, but a write whose own delta is not held is never judged on its own.
- **Deaths** are attributed to the original commit's body only; a snapshot body carrying the same write gets no death record, so its keep bounds are only those of its own deaths.
- **Large values**: no chunk reuse from the current tree (`Reuse`), no streaming read API, `Insert` items of lists are not chunked; page and chunk blobs of a dropped delta are not deleted from the local blob area.
- **Linked frontiers** inside `/tenures` entries are treated as empty (audits drop everything they would have covered) until the node resolves them.
- **Cost**: open replays every commit record; every changing transaction copies the in-memory indexes for rollback; each membership change re-judges every held delta (issues/perm-eval-cost.md); aspect states load and store whole (no paged local state, notes/local-store.md Units); `Timelines::update` walks the whole held set.
- **Re-snapshot and deletion queues** are recorded (`deletions`, `resnapshot` logs) for node-sync; nothing truncates them yet.
