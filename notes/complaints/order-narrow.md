# order-narrow
- A failing `order::` test shrinks for minutes (500 s for 9 tier-1 failures): run with `OSIS_ORDER_SHRINK=0` first when a harness change may fail many tests.
- Mutant runs rebuild the engine each: 6 mutants took 15+ min; `cargo test -- --ignored a b` is fine for two filters after `--`.
- Review: 40 mutants of a rare path say nothing unless you check they fire: `live_kept` etc. "survived" with the path reached 0 times in 40 seeds; an `eprintln` in the mutant settled it. Env-switched mutants in one build (`MUT_ID`) replaced one rebuild per mutant.
- A stray `cat >> /dev/null` in a background script sat on stdin for minutes before the script's file was written.
