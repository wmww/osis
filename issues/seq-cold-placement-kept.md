# A cold seq edit loses a placement the whole state keeps
> Summary: engine pages `seq_cold_edits_keep_placement_plain` fails on main (b82a766c7) at `OSIS_SEQ_COLD_START=689880325750 OSIS_SEQ_COLD_SEEDS=1`: step 155 "placement kept" (writer 1: move 2185 1 3421, delete 359 43), a wrong result, not the budget give-up of issues/seq-cold-edits-follow-gaps.md. Cause not read.
> Priority: normal
> Tags: engine, crdt, tests

Replay: `OSIS_SEQ_COLD_START=689880325750 OSIS_SEQ_COLD_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact engine::pages::tests::seq_cold_edits_keep_placement_plain_spec_crdt_6_1`. Panics at `pages.rs` (a placement the whole-state run keeps differs on the paged run). Check whether it is the follow-gaps give-up compared wrongly or a paging bug of its own.
