# Divergence after a writer's removal (validity re-judge / un-merge)
> Summary: The simulator's `revoke_while_writing` scenario diverges for seeds 98, 244, 271: two nodes holding the same applied commits read different `/s/map` values on the shared thing after node 2's edge is removed while it keeps writing. Suspect the validity flip rebuild (un-merge of map entries) depends on arrival order.
> Tags: node, permissions, crdt, tests

Found by osis-sim phase A (sweep of 300 seeds, release build, at node-core steps 1–2 plus the validity code on main at c2a10ce). Reproduce: `osis_sim::replay("revoke_while_writing", 98)` (also 244, 271); tier-1 regression tests `revoke_regression_*` in sim/tests/scenarios.rs are `#[ignore]` until fixed.

Scenario: 3 nodes, node 0 owns thing A and grants nodes 1 and 2 Write; 100 random steps (random writes over register, counter, max, set, map; lossy, reordering, duplicating delivery; clocks within ±60 s); node 0 removes node 2's edge; 150 more steps; quiescence. At quiescence all nodes hold the same commits and nothing pends, but e.g. seed 98: node 0 reads `/s/map` `{ash: 7, ..}`, node 1 `{ash: 8, ..}`; seed 244: one node keeps key `ash`, the other has none. Only map aspects differed in the failures seen.

Spec: spec/requirements.md (convergence), spec/permissions.md §5.2 (per-delta validity), spec/crdt.md §4.6 (un-merge). Likely place: notes/node.md "Validity" (rebuild as `unmerge(state + held bodies, invalid sources) + valid bodies`) when invalid deltas arrived before vs after the removal.
