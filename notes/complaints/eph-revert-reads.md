# eph-revert-reads
- The seed's failure was pre-existing (fails 80 commits back too); finding that took a second worktree and ~6 min of rebuilds. A note in the issue on how old a gate-found NEW failure is would save it.
- Getting a reader to hold a valid value with no entry took three tries: `hold_blobs` holds the whole listing a blob is in (the node never finishes reading, so never places), `held_to` reorders nothing within a node's log. `hide_blobs` per node was the tool.
- `SyncEngine::own` means "made on this node" (origin), not "authored by this account": a node's own write fetched back after its restart is not `own`. Easy to misread.
