# A cold Seq edit history loses placement at one seed
> Summary: engine `engine::pages::tests::seq_cold_edits_keep_placement_plain_spec_crdt_6_1` fails on main at `OSIS_SEQ_COLD_START=777621519925 OSIS_SEQ_COLD_SEEDS=1`: "step 147: placement kept (writer 1: ["edit", "delete 967 46"])" (spec/crdt.md §6.1).
> Priority: normal
> Tags: engine, crdt, tests

Replay: `OSIS_SEQ_COLD_START=777621519925 OSIS_SEQ_COLD_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact engine::pages::tests::seq_cold_edits_keep_placement_plain_spec_crdt_6_1`. Found by a gate's base replay; not studied. Next: a hand-written reproducer of the step that moves placement.
