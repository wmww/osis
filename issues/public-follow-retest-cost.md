# Public-entry follows are retested at every filter arrival
> Summary: osis-sync tests every sync ID it follows by the public entry alone (`Changed::by_public`) at each peer filter arrival, on every connection: work per arrival in proportion to all such follows, not to what changed; every other sync ID is tested only once its `changed_at` passes `acked_pos`.
> Priority: low
> Tags: sync

Following by the public entry (spec/sync-set.md §2) adds one sync ID per strong of a read unit to an X its key part names that its keys do not open. A removed holder keeping its strong follows X for good. Whether the public reads X shows only in a peer's filter (the peer shows X's public entry once it does), and filters name no sync IDs, so the follower tests all of them at each arrival (spec/sync-opens.md §5 Testing). The count is bounded by held data (the unit's strongs crossed with its key part's edges, each written by the unit's writers and X's admins), but the per-arrival cost goes against "work in proportion to change".

Possible shapes: test a public-entry-only sync ID only against the entries a generation adds; or have a node that holds the public's grant on X tell its account's other nodes (a piece under T's sync ID moves `changed_at`), so only a change of T's unit triggers the test.
