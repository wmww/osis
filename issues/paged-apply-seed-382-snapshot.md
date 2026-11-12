# Paged apply seed 382: whole apply writes a snapshot page-by-page does not
> Summary: paged_apply_matches_whole_large seed 33767158382 fails on main at step 13: the node applying whole commits writes a ContentSnapshot of `t:reg.0` (automatic compaction) that the page-by-page node does not, so their indexes differ.
> Priority: normal
> Tags: engine, tests

- Replay: `OSIS_PAGED_APPLY_START=33767158382 OSIS_PAGED_APPLY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8`.
- The only index difference: an extra local `ContentSnapshot` on `t:reg.0` (author: the applying node) in the whole run. So the compaction trigger fires on one apply path and not the other: whether a node compacts depends on how a commit's pages arrived, which it must not (the trigger should be a function of the held set).
- Next: find which weighing differs (`retention::compact` `candidates`, `Load::of`) between the two paths at that step, and make the test a small reproducer.
