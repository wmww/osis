# The crdt decoder accepts a delta the model rejects for run order
> Summary: osis-crdt's decoder differentials (`tests_decoder::seq_decoder_matches_model_spec_3_3`, `kitchen_sink_decoder_matches_model_spec_3_3`) fail in about one run in six on main: a mutated writer text delta whose runs are out of order decodes Ok in the implementation and is rejected by crdt-model ("run order"). The overlapping-runs check went from `seq_wire.rs` on the claim that the canonical re-encode refuses such input; for this delta it does not.
> Priority: critical
> Tags: crdt, tests

Reproducer from one failing run (the proptests draw fresh seeds per run): delta
`845007070707070707070707070707070707808084098080828603048080808184000300f586060182018182000161638080`,
the implementation's fragment flags 3, 4, 5 and creates 6 (`c` at 1); the model says `Bad("run order")`.
Next: a constructed test of this delta at the writer context of the differential (seed 0, notes/principles.md, Never pin a seed), then either the check back in `seq_wire.rs` or the re-encode made to refuse it.
