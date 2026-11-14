# order: a role commit the held model applies, the node does not

> Summary: `order::held_set_decides_plain` at `OSIS_ORDER_SEED=197373046315 OSIS_ORDER_LEN=60` fails on main: an order at an earlier clock, after 33 ingests, the held model applies role commit #42 and the node does not (its roster keeps one admin). Engine or model bug, cause untraced. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, engine

## Repro
`OSIS_ORDER_SEED=197373046315 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks it). Fails at main 503bace8d alike.

## Direction
Shrink, then decide which side is wrong by spec/permissions.md; fix that side and keep the shrunk history as a default test.
