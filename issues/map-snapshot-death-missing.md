# A map snapshot held before a later put gets no death
> Summary: a node holding a compaction snapshot of a kept `t:map.0` and a later put of a key it holds dates the snapshot's body no death, where a recompute from the same bodies dates it at the put. Honest history; spec/commits.md §5 (a node dates a death at the superseding write its join met; nodes differ in dates, not in whether one is due), spec/crdt.md §4.8.
> Tags: tests, engine, retention

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_map_snapshot_death_missing_spec_commits_5` (order seed 338806): an untyped expiring put of `k0`, a typed write of `k1`, a compaction, an untyped put of `k0`; held: the setup, the snapshot and the last put.

Not diagnosed: the live join may miss the kill, or `Engine::replay_deaths` may date one that is not (the entry holds a struct and a map encoding, a `Slots` position, and the snapshot carries a value-less write). Decide which first. `order::dating` lets a `t:map.0` snapshot have no date where the oracle has one until this is fixed (`skip_map_snapshot_death_missing`; a date given is still checked); remove that with the fix.

Also on main 53453167: `OSIS_ORDER_SEED=7714 OSIS_ORDER_LEN=60` alike_large fails "death dated early or missing" on a `t:map.0` ContentSnapshot whose date is set but earlier than its earliest superseder's (`here` < `earliest superseders`): an early date, which the skip does not cover. Same family or a second bug; not diagnosed.
