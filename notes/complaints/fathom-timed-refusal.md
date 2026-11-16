# fathom-timed-refusal
- A three-node `World` test with a partitioned peer passes `RULE_CAP` (2000 deliveries) from dial ticks alone; the storm message says so, but the cap is per world, not per node (`history::world` scales it by n, a hand-built world does not).
- A "stale refusal by a peer judging the node departed" is hard to stage: before a rotation covering the departure the departed node still opens S by the shared read secret (a Hit), so no ByRole is refused.
- Review: `introduce` fails ("0 redeems 2's card") once a node is paired before it; a node paired after it proves no key actors while its sibling proves the joined card links, so the two are different `Who`s by accident. `siblings()` plus cards redeemed by hand gives two siblings proving only their account.
- Gate passed over its time limits (default-tests wall 2.1x, gate 1.7x) at load 26-32: the rebase onto a base-crate change rebuilt the tree (build 137 s wall) on a busy box.
