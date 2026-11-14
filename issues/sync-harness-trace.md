# The sync harness cannot say why a node diverged
> Summary: a differential or simulation failure prints what a node reads, not what its modules decided; six seed chases (convergence leftovers, dial, holder read, removed write, sweep, redeem) each added throwaway `eprintln!` in opens, pull, read and the engine's ingest, keyed by a node index the product does not see.
> Priority: normal
> Tags: sync, tests

What each chase rebuilt by hand: per node, opens' open/close/NotOpen; streams' joins and leaves with their rejoin cursor; pull's fetched / opened / not opened per entry and the engine's `Ingested` outcome (an `Awaits` commit is dropped silently); read's keep/drop per (S, commit); a sync step the engine refused (`Redemptions::settle` swallows it). notes/coordination.md (Briefs) asks that a diagnosis's prints stay as the harness's failure output or an env-gated dump.

Shape: a `World::trace`-gated per-node event log the modules write through one seam (a `Trace` sink in the node's context, a no-op in the product), printed with the failing script; a failing `check` also prints each node's reads and how many handed commits it lacks.
