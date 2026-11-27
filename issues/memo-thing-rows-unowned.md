# Per-thing memo rows have no owner
> Summary: The rows 47dab4324 added (`thing_syncs`, `secret_actors`, `keys_opens` per actor and thing, `read_floors`; core/engine/src/engine/mod.rs, sync_ids/blobs.rs) are never unfollowed, so memory grows with every thing, and every actor and thing pair, ever read, forgotten things included. Per-commit rows go with their commit (`unfollow_fate`, `unfollow_facts`).
> Priority: normal
> Tags: engine, retention

Against notes/node-closure.md ("derived rows, stored or in memory, by what they derive from"). Fix: drop each row when its thing leaves the held set (`sync::held::forget_actor`, `retention::forget`).
