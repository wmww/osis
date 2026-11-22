# A write to an aspect keeping history costs what the history holds
> Summary: Each small write to an aspect whose history is kept (`History::FOREVER`) costs debug instructions in proportion to the bodies already kept there: 26 M per write over 64 writes, 83 M per write over 256 (osis it, one node). The sync settle re-derives `ReadFacts` (`Engine::read_facts_now`, `body_facts`: `part_covered`, `part_keeps`) for every kept body of the aspect on each write, so n writes cost O(n^2).
> Priority: normal
> Tags: engine, sync, performance

Measured with `tools/icount` on a scratch osis `it` test writing k messages with `listing::say` on `listing::thing` (kept for good): k = 1, 65, 257 gave 0.41, 2.10, 21.6 G. `CPUPROF_INSTR=2000000 tools/cpuprof` on `listing::page_and_listener` (256 writes, 21.9 G, the costliest osis `it` test after the 2000-thing floor): `Node::settle` 92%, `Engine::follow` 89%, the `Cutoff<(SyncId, CommitId), ReadFacts>` refresh 78%, `body_facts` 53%, `snapshot::covered` 26%, `part_keeps` 19%.

What to find: which input every kept body's facts read that each write moves (the aspect's newest write, its snapshot or frontier), and give each body's facts the narrower input it really depends on, so a write moves the facts of the bodies it covers or replaces, not all of them (spec/sync.md §2, Work in proportion to change). Then a count at n and 10n kept writes in a default test (facts refreshed per write).
