# held_set_decides_plain: a node keeps a body a held right holder's snapshot covers
> Summary: `order::held_set_decides_plain` fails on main f9101135d at `OSIS_ORDER_SEED=723062969594 OSIS_ORDER_LEN=60` (emphasis Settings): in the reversed order at an earlier clock, after 66 ingests, held-model says commit #5's `t:reg.0` body is covered by a held right holder's snapshot (so dropped) while the node still holds it. A held-set disagreement, not an emphasis floor.
> Priority: normal
> Tags: tests, node

## Repro
`OSIS_ORDER_SEED=723062969594 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (2 s of checking; fails on main f9101135d). Failure text:

    held [0..71] of 72 commits (base 12): order #1 at an earlier clock Clock { at: 71, early: Time(1700000000418) } [71, 70, ..., 0]: after 66 ingests at Time(1700000000418): held-model differs: commit CommitId(94884050fe9d2f0d..) (#5) on Tid(cenfNLwR7s2sxNqJT2Xn) t:reg.0: the node holds its body, a held right holder's snapshot covers it

The history's emphasis is Settings (retention settings `Setting`, `PurgeSet`, `Demote`, `Compact`, `Undo` steps among the aims). Order #1 is the reverse of the as-made order, judged at an earlier clock (`Clock { at: 71 }`), so a covering snapshot arrives before the body it covers.

## Owner
Order/held-set work is Fathom's area; filed only. `OSIS_ORDER_SHRINK=1` with the repro (9 min) only gets it to 70 commits (the same failure on commit #6, reversed order at clock 67): shrinking does not help; reduce by hand. Next step: decide whether the node or held-model is wrong about the snapshot's cover at that clock.
