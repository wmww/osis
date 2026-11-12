# Undo's snapshot-excuse unit tests no longer reach the snapshot check
> Summary: `unkept_snapshot_without_its_writers_spec_commits_7` and `snapshot_excuses_no_expiring_part_spec_commits_7` (core/engine/src/undo/mod.rs) undo a removal on `x:n.0`, which no setting keeps, so `bounds::setting_keeps` refuses it before `replaced_kept` judges any snapshot; they pass whatever the snapshot rules say.
> Priority: normal
> Tags: engine, tests

Giving `x:n.0` a setting after the writes does not restore them: C's parts are then replaced at the removal, under the setting, so kept, and the undo goes through (checked by hand). The snapshot excuse (spec/commits.md §7, `undo::replaced_kept`) now matters only under the Limit there: a part replaced before a setting kept history on the aspect (or past its bound), with a later snapshot in kept history reaching it. Rewrite both tests over that setup (a part out of history, a snapshot that does or does not excuse it, the undone part kept), or delete them if that path is covered elsewhere.
