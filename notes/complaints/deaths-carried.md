# deaths-carried
> Summary: workflow notes from branch deaths-carried.

- Load average 50-72 during the run: `order::arrival_order_exhaustive_large_spec_crdt_4_8` took 498 s (notes say 106 s), tier 1 alongside it 8.5 min.
- A late-part repro needs `lp.sync_all()` first: a bare `ingest` of another node's commit otherwise waits on `MissingChain`, which looks like a parked commit.
- Squashing with `git reset --soft main` after main moved folds a revert of main's new commits into yours; reset to the merge base instead.
