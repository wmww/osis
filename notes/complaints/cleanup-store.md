# cleanup-store
> Summary: Complaints from the osis-store cleanup.

- `tools/dead_pub.py` found nothing again, but missed three dead items: `WriteBatch::bytes` and `WriteBatch::is_empty` (method names shared with other types, so a name grep counts other crates' calls) and `Store::root_tier` (used inside the crate by its own wrapper). A per-pub-fn count of callers outside the defining crate found `root_tier`; generic method names still need a delete-and-build check.
- The 3-line repeated-window scan found the main target (nine hand-written paged catalog loops in record/nodelog/changed) in seconds.
- Catalog key helpers (`local_key`, `pending_key`, `table_key`) cost more lines than the inline `concat()`s they replaced (+26/-12): reverted. The lesson holds.
- notes/local-store.md and issues/root-key-erasure-tier.md said a diagnostic reports the root tier; nothing ever read it.
