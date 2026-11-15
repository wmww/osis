# A snapshot applied page by page gets no leaving row
> Summary: `Indexes::leaving`/`dated` differ by how a snapshot arrived: applied whole, the snapshot of an aspect whose replace kills a held write gets a row (retention/leaving.rs: "a kill sets the rows of the dying writes' own commits and the aspect's snapshots"); applied page by page it gets none. So the two tables stay out of the index check (`every_index_is_placed_in_the_check`), whose open and rebuild agree on them.
> Priority: normal
> Tags: retention, tests

Repro: move `leaving` and `dated` from `LEFT_OUT` into `tables` (core/engine/src/engine/testing.rs); `apply::tests_paged::snapshot_root_reset_prunes_pages_spec_crdt_8` and `reset_drops_dead_paged_collection_spec_crdt_8` fail: node 3 holds `fill`, receives the snapshot of its replace; whole: rows for `fill` and the snapshot (both at the replace's ts); paged: `fill` only.

Likely cause: the kill dates the aspect's snapshots while the paged snapshot is not yet held whole (`row_at` gives none), and its later pages change the part's state without re-dating it (`date_due` re-dates a changed part only where it has a row or is stripped). Effect where the snapshot carries writes the kill makes leave: their leaving is never told (listeners, node-sync's keep bound). Fix it, then put both tables in the check.
