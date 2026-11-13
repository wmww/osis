# aged-covers
> Summary: Workflow notes from the aged-covers branch.

- Three tests' probes leaned on a writer or reader keeping must-not-hold entries in its own store for lack of a key (`stream::a_readers_deletion_leaves_the_entry`, `sync_more::another_logs_listing_keeps_entries`, `peers_review::a_charged_source_costs_its_row_until_judged`): each failed once the store followed its own judgment, for reasons unrelated to what it tests (an automatic `group.0` compaction, a setting the blocked peer never got). Tests on entries in a store should keep history on the aspects they probe.
- `sync_more::a_listing_past_the_deletion_horizon_*` now pass by either mechanism (the trimmed listing, or the reader's own judgment of v0 once it holds v5): their probe no longer isolates the listing.
