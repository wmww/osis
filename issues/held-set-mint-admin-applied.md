# held_set_decides: a commit with a mint-admin part applies at the node, not in held-model
> Summary: osis-engine `order::held_set_decides_plain` at OSIS_ORDER_SEED=852227602733 OSIS_ORDER_LEN=60 (PartsAway, every commit held): a commit whose part writes a new thing's `map.0` with a mint admin applies at the node and not in held-model; fails on main as on a branch touching no engine source.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=852227602733 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (OSIS_ORDER_SHRINK=1 shrinks it). Message: `held-model differs: commit … (#60) applied: model false, node true; parts ["… t:map.0 mint admin Some(…)"], node misses Some([])`. Not yet read: which of the two is wrong (the model first, notes/principles.md).
