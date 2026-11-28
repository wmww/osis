# A revoked node following its old grant's signal holds the thing's content pending
> Summary: since the local-part log (b6324e053), a node whose grant is removed keeps following the grant's signal (its fire stays in the inbox's held history), so it holds the thing as a stub and syncs its sync ID; the sim hands it the thing's content, which pends outside its node closure and never leaves: `sim-sweep:revoke_while_writing` seed 0 is "not quiescent after 50 rounds; pending per node [0, 0, 40]".
> Priority: normal
> Tags: engine, sync, tests

Content of a thing held as a stub alone should count as never received once the pass that brought it ends (spec/commits.md §4 Outside the node closure, §5 Dropped when the pass that brought it ends); either the sim harness ends no pass for a stub's sync ID, or the engine keeps such parts carried. Also open: whether a signal for a removed grant should still be followed (spec/sync-inbox.md §5: followed while held and its holder is read).
