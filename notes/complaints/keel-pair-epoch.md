# keel-pair-epoch
- The issue's diagnosis (two epoch-2s, a fork) was wrong: one epoch 2, the new node simply lacked K's boxes to its account. A 30-line dump of each node's epochs, rosters, tickets and sync ID entries found it; guessing from the issue text would have chased forks.
- Probing needed throwaway pub hooks in osis-engine (`testing.rs`) and a global flag to limit traces to one phase; there is no harness tool to print "where did node i learn secret e of t".
- `World::new(seed)` worlds in a loop (seeds 0..8) were the fastest way to see the failure was the common case (6 of 8 seeds), not a rare ID order.
