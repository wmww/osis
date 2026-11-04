# order-narrow
- A failing `order::` test shrinks for minutes (500 s for 9 tier-1 failures): run with `OSIS_ORDER_SHRINK=0` first when a harness change may fail many tests.
- Mutant runs rebuild the engine each: 6 mutants took 15+ min; `cargo test -- --ignored a b` is fine for two filters after `--`.
