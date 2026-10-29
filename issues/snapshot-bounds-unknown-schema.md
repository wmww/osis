# A snapshot of an aspect whose schema the node never registered has no keep bounds
> Summary: `Engine::snapshot` takes the aspect's default bounds only from schemas registered at this node (`Core::schemas`: `register_schema`, or a local typed write; in memory, empty after a restart until one of those). Otherwise the snapshot is written `writer` with no bounds, contrary to spec/commits.md §5, so a keep-at-most aspect's content outlives its bound in that snapshot. Needs a rule for a node without the schema.
> Tags: security, engine, retention

Where: `retention/mod.rs` `Engine::snapshot` (`schema = ... tx.core.schemas.values().find(...)`), `framing_for` -> `snapshot_retention(ak, None)`.

Who hits it: node-sync compaction and the purge re-snapshot duty at a writer that holds the aspect but never wrote it in this process (a fresh device, a restarted node before the app registers its schemas, a node without the app). Tests work around it by writing the aspect first (`validity::dropped_snapshot_frontiers_count_spec_commits_5`, `bound_dropped_coverer_still_carries_spec_commits_5`).

Options: refuse to snapshot (and skip compaction) when no known schema declares the AK, and say in spec/commits.md §5 that a writer without the schema does not snapshot (the purge re-snapshot duty then falls to writers who have it); or persist registered schemas so a restart keeps them; or both. Headers carry only `(SchemaId, revision)`, so a receiver cannot learn the bounds from the wire.
