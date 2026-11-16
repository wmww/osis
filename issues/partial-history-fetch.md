# A node that stops fetching old history
> Summary: A new node fills newest first and whole (spec/sync-judgement.md §2), so a long chat opens in seconds to minutes; what is left is a node that never fetches old messages, on-demand pages, the cost of listing, and a node short on storage evicting bodies. Tess: "a holder that cannot read old content and one that chose not to fetch it may be the same state" (issues/history-less-grant.md).
> Priority: low
> Tags: sync, api, performance

Built: priority, not partiality. Numbers: notes/test-scale.md, Scale checks.

Not built, each needing a reason from use first:
- **A cap**: a node-local "no older than". The fill stops at it. `complete` stays false for good, so `wait_synced` and a demotion's pre-sync need another answer than a caught-up source (spec/sync-status.md §1); deletions stay held (`unopened`), so a capped node would need not to count what it chose not to fetch, or it never deletes. Must-hold stays judged on held bodies only.
- **On-demand pages**: move a page's range to the front of the queue. Small once a cap exists; pointless before, as the fill reaches them.
- **Listing cost**: every entry is listed before the first body, about 160 B and 90-115 us each here, most of it verifying the stamp: about 2 min and 160 MB at 10^6. A batch signature check, or checking stamps only on arrival, would cut the time; a filter at a peer that cannot read cannot, as such peers cannot tell blobs apart.
- **Stated limits**: a writer marking a flood order 0 delays the newest page, passes and a redeem by its size. Wraps under many epochs try each secret, as all reads do.

## Evicting held bodies
A node drops only covered, expired or purged bodies, so a node short on storage (a phone in a busy realm, a reader without write) holds every body until a writer compacts. The state is the join of the held bodies (spec/crdt.md §4.6), so evicting a body loses its live writes from reads. Shapes, none designed: a node-local snapshot that is not a body (a second state); evict-and-refetch of bodies whose writes are dead in the join (only dead bodies of kept history qualify); a reader asking a writer to compact (a request, not a right). Not promised by spec/requirements.md.
