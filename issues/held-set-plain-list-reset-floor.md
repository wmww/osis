# held_set_decides_plain: a seed set whose Lists seeds judge no list element reset
> Summary: `order::held_set_decides_plain` at `OSIS_ORDER_START=712821043672` (8 seeds, plain size) fails its coverage floor "Lists seeds ran, but held-model judged no list element reset": every seed passes the oracle, but the Lists emphasis's seeds there reach no `list element reset` (`held::REMOVALS`).
> Priority: normal
> Tags: engine, tests

- Replay: `OSIS_ORDER_START=712821043672 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain`. Fails alike on origin/main ee03fe8a5; passes from 0.
- A floor per emphasis over few seeds is a coin toss when its generator reaches the outcome only sometimes: either the Lists generator must reach a reset by construction in every seed (a reset step forced into its start), or the floor must count over enough seeds to be sure. A harness fix, not an engine one, unless the reset is unreachable for an engine reason.
