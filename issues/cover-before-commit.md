# Purge-on-replace strip: a cover written before its commit
> Summary: A snapshot written by a node holding a part's reacher but not yet the part's commit lists none of that commit, so once it covers the reacher a new reader counts the stripped part never received, for good.
> Priority: low
> Tags: engine, sync

A part dropped as covered strips under purge on replace while a held valid snapshot reaches it by its tables (spec/sync-judgement.md §2 Per blob). A snapshot lists every commit its writer holds with a part on the aspect (spec/crdt.md §8), so the snapshot Y covering the reacher X normally still reaches the part. Not where Y's writer held X but not yet the commit C: Y lists nothing of C, its holders drop X, and a reader joining later holds Y and C stripped, counting the part never received with no source. The same order leaves the part unstripped where no holder of X writes again (held-model `strip`).

Untested at the engine level: needs a snapshot written while its writer holds a reacher and not the commit.

Rejected: Y listing every source X lists (grows with history: a source outlives every commit of it); X kept beside Y until Y reaches all X reaches (order-dependent: a reader may drop X before C arrives).
