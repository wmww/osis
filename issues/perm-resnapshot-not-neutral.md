# Re-snapshot changes a roster answer
> Summary: osis-perm tier 2 `roster::snapshot_resnapshot_neutral_large` fails at `OSIS_PERM_SEED=3313` (periodic run 3, main before perm-joint-model): shard seed 0x5eed0df7 sample 556, re-snapshotting a roster changes an Admin edge to Write and applies one more op (000003ef). Check first whether perm-joint-model (kept standings, item 46) fixed it.
> Tags: perm, tests

Replay: `OSIS_PERM_SEED=3313 cargo test -p osis-perm --test it -- --ignored roster::snapshot_resnapshot_neutral_large`.
