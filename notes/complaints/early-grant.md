# early-grant
> Summary: workflow notes from the earlier-ordered-grant (sync ID fork) fix.

- The issue's framing (evidence placement, cycles) pointed away from the cause; `OSIS_SYNC_TRACE=<node>` plus `Engine::carrying` per node showed in minutes that the reader synced another sync ID of T than the writers. A `World` helper printing each node's sync IDs per thing beside `why_role` would have shortcut it.
- No describer for a commit ID in tests (which commit is the grant, the rotation, the re-seal): the trace's `+commit C..` lines are opaque; identifying them took env-gated probes in the engine.
