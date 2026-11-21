# The quiet cover has no test
> Summary: No test reaches the writer's cover once an aspect is quiet (`Trigger::quiet`, `QUIET_MS`, notes/engine-retention-trigger.md Cover once quiet): that a small leftover gets one snapshot after the quiet time, none during a stream of writes, and none set off by a snapshot.
> Priority: normal
> Tags: tests, engine

notes/engine-retention-trigger.md, Cover once quiet, describes the rule; nothing checks it. Owed, each with seed 0 and a constructed setup:
- an expired write's leftover below `FACTOR` in a quiet aspect: after `Engine::tick` past `QUIET_MS` the writer writes one snapshot, and a node that missed the write reads the leftover's creations and resets from it;
- writes or expiries less than `QUIET_MS` apart: no quiet snapshot until they stop; the deadline consumed, at most one per writer per quiet time (kept owed where the node may not write);
- no storm: a snapshot neither arms nor postpones; another writer's snapshot drops the leftover here;
- an open arms every aspect holding a value-less write.
