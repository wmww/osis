# A destruction after a purge by author leaves a dated row
> Summary: One node: two `set`s on one aspect, a purge request by author naming the node, then the thing's destruction: the engine's end-of-history check (`retention::leaving::rows_exact_on`) finds a commit's `ix.dated` row still dated where the held set dates it nowhere. Probed, not fixed; not an accounts bug.
> Priority: normal
> Tags: engine

Reproducer (CLI, in-memory store, one node): `kept_thing`, `set T note:m.0 "one"`, `set T note:m.0 "two"`, `purge T note:m.0 --author <the node>`, `purge T` (destroy). At the end of history: `<commit> on T note:m.0: its row vs its date from the held set`, the row `Some(ts)`, the held set `None`. Each step alone passes: without the purge by author, or without the destruction (purge by commit then destruction passes too), no row is left. So a row written for the author purge's dating (the purged parts, or the snapshot a writer may add of the aspect) is not dropped when the destruction takes the thing.

Test: CLI `writes_and_purge_commands_plan_cli` (ignored on this issue). An engine test of these four steps is the reproducer to write; then find which part's row the destruction keeps.
