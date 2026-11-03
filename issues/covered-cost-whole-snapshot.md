# `covered` walks the whole snapshot per body
> Summary: one `covered` check costs about the snapshot's size, not the body's as its comment says: 60 ms at a 20k-char text snapshot, 447 ms at 100k (200 and 1000 bodies of 100 chars), so judging each body once is 447 s at 100k and grows with bodies times size. A register is 33 µs. Older than join-only cover (no-gap checks cost the same on main).
> Tags: engine, performance

Measured on the `test` profile, one process, `Engine::covered(snap, c)` for every body of a text aspect. Not yet looked at: which of `part_at`, `copy_index`, `encode` takes it. `drop_covered` settles each pair once, but `must_hold` and `carried` judge bodies per pass. A bound first needs a measured budget (notes/testing.md, Performance budgets).
