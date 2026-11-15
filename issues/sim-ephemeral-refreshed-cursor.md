# Sim `ephemeral`: a node misses a refreshed cursor
> Summary: sim-sweep `ephemeral` fails on main at setup 393591877074, seeds 393591877085 and 393591877087: at step 300 node 2 does not read node 0's refreshed cursor (`sim-sweep --seeds 1 --from 393591877085 --setup 393591877074 --only ephemeral`, 1-5 s). Found by the fork-sides final review's gate; not chased.
> Priority: normal
> Tags: sim, sync, ephemeral, tests

The scenario's oracle (notes/ephemeral.md, Tests: a refreshed cursor is owed through nodes whose clocks are before its expiry) says node 2 should hold node 0's cursor; whether the sync or the oracle is wrong is open. Sync is frozen for its rewrite: check it against the rebuild before fixing on the old code.
