# Automatic durable compaction fails six sim scenarios
> Summary: With the compaction trigger on for durable data (branch durable-compaction), a 15-seed sweep fails 32 seeds in six scenarios that pass on main: revocation_bob/carol (a removed writer's tag writes still read), large_edits (an edit sends about twice its new chunks), snapshot_rights (a body stays at the host past its bound), coverer_revoked (W never gets S1 back), label_replacement_offline. All but three large_edits seeds fail at the branch's first commit too, before its test re-derivation.
> Priority: critical
> Tags: engine, node, sim

Blocks merging durable-compaction. Replay any with `osis_sim::replay("<scenario>", <seed>)`; seeds 0..15 at the sweep's default size.

- **revocation_bob** (seeds 2, 5, 10, 11), **revocation_carol** (0, 1, 3, 6, 8, 10, 11, 14): node 0 reads tags `{"mon", "x", "y"}`, expected `{"mon"}`: writes the revocation should take away stay in the read. Likely a compaction snapshot carrying the revoked writer's writes that the removal's frontier does not reach, or a snapshot of the revoked writer standing; check the oracle's model of snapshots before the engine.
- **large_edits** (15 of 15): "edit k by node n: sent X B for Y B of new chunks", X about 1.5-3 Y: a snapshot of a large value goes up with the edit (its tree nodes or chunks re-sent). Either the snapshot must link existing pages (issues/zero-growth.md To check) or the budget must count the snapshot.
- **snapshot_rights** (13, 14): "AuthorOrAdmin bound 0: body of node 1 at the host true, should be gone false".
- **coverer_revoked** (4, 13): "W never got S1 back: Some((true, false))".
- **label_replacement_offline** (10).
