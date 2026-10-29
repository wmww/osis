# No own cover past the page target
> Summary: Ephemeral deltas are not paged, so once an author's own state of one aspect passes `PAGE_TARGET` (64 KiB) no own cover can be built: its commits are no longer compacted and pile up at holders and servers until the server cap refuses them (that label then stops syncing there for the author's later writes). Found in the eph-own-covers review (`ephemeral::cover_past_page_target_loses_no_write_spec_sync_9`: before the fix a failed cover also dropped the unsent writes it joined).
> Tags: engine, ephemeral

- Today: `compact_own_ephemeral` reports `EphemeralRefused` and weighs again once the held commits double (`cover_est`), so the cost stays O(1) per byte; the sim and `random_window` states stay far below 64 KiB and do not reach it.
- Fix direction: page ephemeral deltas like durable ones (pages in memory with the entry, carried as blobs of the commit), or split a cover by aspect so only that aspect is stuck. Also the take path: a single write batch past the target is not sent at all (notes/ephemeral.md Step 3, Open).
