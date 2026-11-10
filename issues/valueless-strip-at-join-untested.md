# No test needs the value-less strip at join
> Summary: `join_into_state`'s `strip_valueless` is the only thing keeping a fresh body's copy of a write held value-less (an undelete's copy, a stale copy, a snapshot's) out of the state, and no test reaches that case: dropping the call fails no default test, even with the rebuild check run on every touched aspect.
> Priority: normal
> Tags: engine, tests

Measured with a probe logging every join where the strip removed something: the default tests (engine lib, node, osis, sim `it`) hits it about 510 times, all in osis-node `it` (`parts::forged_parts_beside_a_part_past_expiry_alike_spec_commits_4`, `shred::`, `order::expired_late_part_joins_valueless_spec_crdt_4_7` and others). Every hit that changes the joined state is a late part of a known commit (`join_late`) whose own writes are value-less; the same transaction then holds it value-less (`retention::on_late` -> `hold_valueless`) and rebuilds the aspect, so the end state is right without the strip. The one hit on a fresh apply (`review::purge_drops_late_snapshot_spec_commits_5`) changes nothing.

Missing: a test where a body arriving in its own transaction carries a copy of a write already held value-less here (expired or purged), with nothing else rebuilding the aspect: a snapshot copying an expired write, an undelete of a char whose insert expired, a stale certificate copy. It must fail with the strip removed (by the read, or by the rebuild check). held-model's generator may reach it in its property runs (`held_set_decides_plain`); not checked.
