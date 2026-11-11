# crdt_equals_model: expiry does not commute with join (seed 952327621198)
> Summary: osis-crdt `tests_model::crdt_equals_model_large` fails "expiry commutes with join" at one seed of 1000 (replay: `OSIS_CRDT_START=952327621198 OSIS_CRDT_SEEDS=1 OSIS_CRDT_SEED=952327620837 cargo test -p osis-crdt --lib -- --ignored --exact tests_model::crdt_equals_model_large`). Fails on main too (found by the history-3 gate; that branch does not cause it). The two sides differ in a text sequence under a map entry after an expiry; the property it breaks: expiring a write gives the same state whether before or after a join. Needs a minimal reproducer and a class look, not a pinned seed.
> Priority: normal
> Tags: crdt, tests
