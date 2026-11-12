# A settled node loses a roster edge the keep-everything node holds (plain seed 38534)
> Summary: `order::held_set_decides_plain` seed 38534 (Settled emphasis) fails on main: given the whole set as made at an earlier clock, then settled, a node's `roster` of one thing lacks a Write edge that the node keeping every body holds (Read and Admin edges agree). Not a held-model difference: the order oracle's settled check. History has purges (`Purge`, `PurgeAuthor`), demotions and forged snapshots; not shrunk. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, node, retention

## Repro
`OSIS_ORDER_SEED=38534 OSIS_ORDER_LEN=60 tools/heavy cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (4 s). `OSIS_ORDER_SHRINK=1` shrinks it. Possibly the same shape as issues/order-settled-seed-62510.md (also Settled, also purges).
