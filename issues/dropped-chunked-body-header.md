# Dropping a chunked body as covered can leave its header unresolvable
> Summary: When the compaction trigger drops a live chunked value's body (an aspect no setting keeps), the node can no longer open from its persisted index: `local_serve::local_work_sets_match_full_passes_*` fails its reopen check with `Corrupt("header lists")` on that content commit (its chunk list goes by link, and the link's blob is gone). `sync_more::reencrypted_chunk_keeps_concurrent_edit_*` reads `Data(Missing)`. Both pass with the trigger off; likely reachable on main by an explicit compaction of a replaced chunked value.
> Priority: critical
> Tags: engine, node, data-loss

Found on branch durable-compaction. Suspect: node-sync's `forget_dropped` deletes the dropped commit's `view.chunks` (`dropped_chunks`), which seems to include the blob the header's chunk list resolves from (`Header::links`), while the header stays (not forgotten yet). A header's own list blobs belong to the header, not the body: they should go only when the header does.
