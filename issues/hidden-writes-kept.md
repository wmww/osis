# A write hidden in a removed entry keeps its bytes until a reset
> Summary: An edit concurrent with an entry's removal is hidden, never dead (spec/crdt.md §4.8), so keep-at-most never drops its body, snapshots carry its value and the removed key, and no op reaches it: `remove` acts on live records only. Only a reset of the map or a purge. A purge of the edit takes its value but leaves the key its record repeats. Honest flow; needs a concurrent edit. Reads never show any of it.
> Tags: security, crdt, engine

Repro: osis-node `waits::hidden_write_goes_under_keep_at_most_repro_spec_commits_5` (ignored). Same bytes before removal became final, but then the write read, so a user saw and could remove it. Holds for a hostile key copy too (was issues/purge-keeps-repeated-key.md: reads closed, a dot no delta owns keeps the key in state and snapshots; notes/core-triage.md 2.4 takes hostile residue as a limit).

Sweeping in the lattice fails: a record's reset is pruned by a parent reset, so "reset drops all under it" depends on order (`lattice_laws`), and a value-less hold is not monotone either.

Simplest rule found: compaction sweeps. Before it snapshots, a writer re-removes every record holding a reset that also holds a write, with an ordinary removal at its own stamp. No lattice or wire change; the writes die, bodies drop, keys go. Only records with a seen removal or expired creation: a record merely lacking its creation may be a partial receipt, and sweeping it would lose data. Costs a small commit per hidden edit, and a removal so repeated stays when the first remover turns out invalid.
