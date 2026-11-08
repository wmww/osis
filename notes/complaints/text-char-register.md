# text-char-register
- An ephemeral undo test accepted `UnknownCommit` as a pass, so it never checked what the undo restored: ephemeral bodies have no keep bounds and compaction forgets them on the first pass after expiry. Moving the clock alone (`net.clock.advance`, no wakes) undoes before that pass.
- Deltas are pruned in several writer paths (batch overlay checks, codec `prune_stable`), so a new prune rule also binds what writers may emit: check the writer's net effect before adding one.
- Review: osis-vectors checks only that a `reject` case is rejected, not the rule named, so a wrong rule label passes (checked by hand with a probe print).
- Review: 2 of 20 random `seq_decoder_matches_model_spec_3_3` runs failed on issues/seq-snapshot-pos-below-reset.md's class (non-winning writes below a reset), not this branch; telling them apart took reading the dumps.
