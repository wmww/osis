# A part that counts as held but is held without its pages: arrival order decides
> Summary: a commit on two synced things, its H part expired (or past keep at most, purged, listed by a snapshot), so it counts as held, and that part's pages away. The G part first applies the commit and the H part then waits alone; the H part first holds the commit whole, for good when the pages left with the body. So "already applied" can differ between orders with one held set and sync set. The same with a parked part.
> Tags: engine, spec

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_counted_as_held_part_order`.

Not new with parts waiting alone. Rare: needs a part to arrive after its pages left. Fix sketch: a held part that counts as held by the rules for a missing delta holds nothing back: in `examine`, a page or parked wait on it goes aside like a late part's. Spec/commits.md §4 needs the same sentence.
