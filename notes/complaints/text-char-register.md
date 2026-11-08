# text-char-register
- An ephemeral undo test accepted `UnknownCommit` as a pass, so it never checked what the undo restored: ephemeral bodies have no keep bounds and compaction forgets them on the first pass after expiry. Moving the clock alone (`net.clock.advance`, no wakes) undoes before that pass.
- Deltas are pruned in several writer paths (batch overlay checks, codec `prune_stable`), so a new prune rule also binds what writers may emit: check the writer's net effect before adding one.
