# eph-purge
- `LocalPeer::package` of an own memory write under purge on replace returns `None`: the writer's own cover drops and forgets it in the same transaction. Tests must take the cover's bytes instead; cost a debug round.
- Mid-tx class routing is easy to get wrong: `remove_pending` then `put_pending` of a memory commit's pending copy in a durable transaction (a purge request applying) writes the copy durable, since the remove takes it out of the overlay first. Needs `in_class` around every rewrite; nothing asserts it outside debug `durable_get`.
- The issue's frontier question took most of the time: whether a frontier passing a purged body loses anything turns on `covered_join`'s `!held` path (traced and missing reads covered), which no note states.
