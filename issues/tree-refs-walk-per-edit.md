# A large value's edit walks its whole tree

> Summary: each edit of a large value re-walks the value's whole state tree (`tree_refs` state memo, read again whenever the state moved) when a body drops or the compaction trigger weighs, so per-edit work grows with the value's size.
> Priority: low
> Tags: engine, retention

`tree_refs::trees_of` for `Source::State` walks every node of the value and collects every blob it links; the memo keeps it only while the state is unchanged, so each edit pays it again at the next question: a body's drop (`chunks::released`, node-sync `delete.rs`) and the trigger's weighing (`compact::candidates`, `state_refs_in`). Counted in `compaction::trigger_work_flat_in_value_size_spec_sync_7`'s scenario (6 edits): `tree refs: tree blobs` 198 at 8 chunks, 1188 at 80; without the weighing's walk 132 and 792, so the drop path alone already scales so. That test counts only `compact: tree blobs sized` and `compact: bodies weighed`.

Fix direction: answer "does a live state link blob X" from what the edit changed (the old and new root paths: a delta's reach), not from a fresh walk of the whole tree; then add `tree refs: tree blobs` to the flat test.
