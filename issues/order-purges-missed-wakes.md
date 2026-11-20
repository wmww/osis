# order: a full scan applies pending commits the wakes missed (Purges)
> Summary: `order::held_set_decides_plain` at seed 260367750456 (Purges, OSIS_ORDER_LEN=60) fails "applied by a full scan, missed by the wakes" (`Engine::lost_wakes`): some arrival or purge moves what pending commits wait on without the `Wake` they are parked under. Fails on main's binary; no store failure involved.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=260367750456 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (fails within 10 s; `OSIS_ORDER_SHRINK=1` shrinks it). Four commits missed at the first failing step (`on the way to Order(0, 8)`), more on other orders.

Next: shrink, find which change to the held set or purge state lets the four apply, and which `Wake` (notes/sync-facade.md, Pending) should have named them; a missing wake source, not a lost signal (the store never fails in this harness).
