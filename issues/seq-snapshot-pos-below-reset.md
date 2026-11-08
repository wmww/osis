# A text snapshot carrying a position write below its own reset decodes
> Summary: `tests_decoder::seq_decoder_matches_model_spec_3_3` (proptest seed 8198447941242475734) fails on main: a mutated text snapshot with a seq reset at wall 1572864 and elements whose second `pos` write is stamped below it (wall 2) decodes Ok in osis-crdt, while the model rejects it as carrying a write its own resets prune (§3.3 rule 7, notes/crdt.md Prune-stable deltas). It breaks the gate at random.
> Priority: critical
> Tags: crdt, tests

Replay: add `cc 88e788c0bf1cda72e723863b7dbecc582d0b06c94990320e709db7c167a1a5bf # shrinks to seed = 8198447941242475734` to core/crdt/proptest-regressions/tests_decoder.txt and run `cargo test -p osis-crdt --lib seq_decoder_matches_model` (do not commit the line: turn it into a small reproducer). The implementation's prune-stable check (`codec::prune_stable`) seems to miss a sequence element's non-winning `pos` write below the sequence's reset in a snapshot; found gating undo-replaced, which does not touch osis-crdt, so likely from expiry-2's strip and prune changes.
