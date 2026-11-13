# A paste fails when a clipboard dot is inside a placement row
> Summary: `Op::Paste` finds each clipboard dot with `Lin::index`, which finds only a row's first dot; where hidden clipboard chars share a row (a placement built by a whole pass, e.g. after a snapshot load) the paste fails though §5.7 says it succeeds.
> Priority: low
> Tags: crdt

Repro: set "one two three", `cut_dots(4, 4)`, delete those 4, round-trip the state through `encode_snapshot`/`decode_snapshot`, then `Op::Paste { dots, at: 9 }`: fails on the decoded state, succeeds on the live one. The writer falls back to inserting (no convergence issue; replicas apply the written records), but the paste's outcome depends on how the writer's placement cache was built, not on its state. No API exposes paste yet (issues/api-deferred.md). Fix: look a dot up by the row holding it (row dot plus offset within its span), and cut the slice at element granularity.
