# Purged large values keep their chunks at blind nodes
> Summary: The sync pass never judges chunk, tree-node or page entries ("not judged: entries not opened"), so a purge or keep-at-most drop of a large value deletes its commit blobs at servers but leaves every chunk blob; spec/requirements.md (Deletion) wants an author's purge to remove the chunks it wrote and an admin's to remove all.
> Tags: security, sync, node

Repro: osis-node `tests/hostile_server.rs` `purged_chunks_leave_the_server_spec_sync_5` (ignored): a 300 KB string on a writer-purgeable aspect, purged by the admin; all 3 chunk blobs stay live at the server after two passes.

- Impact: the ciphertext stays; its key travels only in the purged delta's link, which honest nodes dropped, so it is readable only by a party that kept the delta (a dishonest node), which the requirement still rules out at untrusted nodes. Expiry is unaffected (chunk prefixes carry it and servers expire them).
- Direction: when a body becomes must-not-hold, also judge the chunk/tree/page/link-page blobs its deltas created (the header's chunk list per delta) that no held live delta references (chunk reuse, spec/sync.md §1), and delete them by the chunk tokens (their prefixes carry the creating delta's commitments, spec/crypto.md §7) or the delete key; an author deletes only the chunks its own deltas created. Compaction drops need the same.
