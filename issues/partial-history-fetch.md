# A node that stops fetching old history
> Summary: A new node now fills newest first and whole (spec/sync.md §6, notes/node-sync.md First sync), so a long chat opens in seconds to minutes; what is left is a node that never fetches old messages, on-demand pages, and the cost of listing. Tess: "a holder that cannot read old content and one that chose not to fetch it may be the same state" (issues/history-less-grant.md).
> Priority: low
> Tags: sync, node-sync, api, performance

Built: priority, not partiality. Numbers: notes/testing.md, long aspect table.

Not built, each needing a reason from use first:
- **A cap**: a node-local "no older than". The fill stops at it. `complete` stays false for good, so `wait_synced`, a demotion's pre-sync and `label_passed` need another answer than a finished pass; deletions stay held (`unopened`), so a capped node would need not to count what it chose not to fetch, or it never deletes. Must-hold stays judged on held bodies only.
- **On-demand pages**: move a page's range to the front of the queue. Small once a cap exists; pointless before, as the fill reaches them.
- **Listing cost**: every entry is listed before the first body, about 160 B and 90-115 us each here, most of it verifying the stamp: about 2 min and 160 MB at 10^6. A batch signature check, or checking stamps only on arrival, would cut the time; a host-side filter cannot, as hosts cannot tell blobs apart.
- **Stated limits**: a writer marking a flood order 0 delays the newest page, passes and a redeem by its size. Wraps under many epochs try each secret, as all reads do.
