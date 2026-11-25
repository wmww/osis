# A lowered writer's invalid writes: the test's outcome moves with the draws
> Summary: osis-sync `growth::a_lowered_writers_invalid_writes_leave_nothing_*` reaches its precondition by the draws: with the same `lowered()` world, `lowered_writes(n)` fails its own "node 2 took the writes" check at n = 12, 18, 30 and passes at 10, 14, 16, 20, 22, 25 (deposited rows per node then [1, 0, 2] at every n). Node 2, cut off from node 0, should take every write node 1 believes valid; which rule leaves it without the first or last is not found.
> Priority: normal
> Tags: tests, sync

notes/principles.md (Never pin a seed; how often is not whether): a precondition that holds at some n and not others is a real behaviour the test happens to step around.

- **Seen**: probed by running `lowered_writes(n)` for n in 10..30 under `catch_unwind` (a throwaway test). At the n it fails, node 2 lacks `bad[0]` or `bad[n-1]` after the first `w.run()`; at every n it passes, the stores' deposited rows match (the flat check passes). An earlier base had node 2 keep one more deposited entry at 20 than at 10 (a content `u:n.0` commit under one sync ID), so the census comparison can also move.
- **Wanted**: which write node 2 misses at n = 12 and why (delivery while node 1 writes, a cap, a deposit refused), as a constructed test that fails without a fix; then the census at 10 and 20 judged with that settled.
