# A removed writer's last write is read by arrival order
> Summary: a writer's write made just before its removal, which the other writer received, is read by that writer and by the reference engine but not by the remover, though the remover holds every commit they hold: what a node reads depends on arrival order (spec/requirements.md Convergence). Ignored test `flows::a_removed_writers_last_write_reads_alike_at_every_holder`.
> Priority: critical
> Tags: sync, engine

Property: nodes holding the same commits read alike (spec/requirements.md Convergence; spec/permissions.md §5.2 Addenda and §6: a demoted writer's writes survive where another writer had received them by the demotion's `ts`, else every writer drops them).

Trace (clean differential, seed 347110580059 shrunk from 46 steps): node 0 makes thing 1 and writes v3; grants node 1's account write; writes v4; grants node 2's account write; run; node 1 writes v5; node 0 removes node 1 (no run between, so node 0 has not seen v5); healed, run to quiet.

At quiet: the reference (a bare engine handed every commit, v5 before the removal) and nodes 1 and 2 read v5; node 0 reads v4. Every node holds v5's commit. Handing node 0 every commit nodes 1 and 2 hold by hand (`history::hand`), so it holds all 46 the reference holds, still leaves it reading v4.

So sync delivered everything; the split is in judgement:
- Either node 2, receiving v5 at the removal's `ts` (no world time passes between steps), writes no addendum listing it, and nodes 1 and 2 read v5 only because it arrived before the removal there; then v5 should be lost everywhere and the reference (which also took v5 first) is wrong too.
- Or node 2's addendum exists and node 0, the removal's author, does not let it bring v5 back (an edit dropped as invalid and not judged again when it counts again).

Suspected module: the engine's demotion judgement (spec/permissions.md §5.2 Addenda, §6 Invalid deltas), Fathom's area; the reference's arrival order (`history::reference` hands commits in the order seen) hides the first reading.
