# Ephemeral blobs listed by a later commit stay at hosts
> Summary: An ephemeral commit lists every ephemeral blob its deltas link, those of other commits too (a reused chunk, a tree a snapshot carries). When the last commit listing such a blob is forgotten, node-sync deletes it at hosts with that commit's delete keys, but the blob's prefix commits to its introducer's keys: the host refuses, and the blob stays there (counted against the label's host cap) until the host restarts.
> Priority: normal
> Tags: ephemeral, node

- Where: `pass/delete.rs` `dropped_chunks`/`chunk_delete` (a forgotten memory commit's `ChunkEntry` keys sign the delete), `engine/write.rs` `build_and_apply` (a memory commit lists the memory blobs it links).
- Locally nothing leaks: a node releases a blob once no held commit lists it (`unindex_commit`).
- Fix direction: per-blob delete authority not tied to the introducing header (branch `chunk-blind`: a linked blob's blind comes from its blob key, and a snapshot lists every blob it links); once it is in, the delete of such a blob verifies and this issue goes.
- Test: a 20 MiB ephemeral value carried by a snapshot of another writer (reuse or compaction), then replaced and compacted again: none of its blobs is at the host.
