# A cold sequence edit keeps its placement where the oracle expects it laid out anew
> Summary: `seq_cold_edits_keep_placement_plain_spec_crdt_6_1` fails on main at seed 433811979068: step 159, writer 1's two inserts (`insert 3100 2`, `insert 3101 1`) leave the placement not held while the delta is on no cycle (`placement kept`). Not yet told apart: an engine fault or an oracle too strict.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_SEQ_COLD_START=433811979068 OSIS_SEQ_COLD_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact engine::pages::tests::seq_cold_edits_keep_placement_plain_spec_crdt_6_1` (about 5 s). Seen by a gate's random offset; the assert is in the property's `Place` match (core/engine/src/engine/pages.rs, `assert!(cyc, ...)`).
