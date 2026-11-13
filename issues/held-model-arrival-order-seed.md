# held-model: arrival orders read differently after repair at one seed
> Summary: `props::arrival_orders_read_alike_after_repair_large_spec_commits_5` fails at seed 428367310133 (order 0) on origin/main: one content aspect reads "bbe" in the full settle and nothing after a shuffled arrival.
> Priority: normal
> Tags: tests, held-model

Reproduce: `OSIS_HELD_START=428367310133 OSIS_HELD_SEEDS=1 cargo test -p held-model --test it props::arrival_orders_read_alike_after_repair_large -- --ignored`.

The differing part is a Register write under admin retention whose fate in the shuffled order is `Leftover(Purged)` while still valid: the shuffled settle purges a write the whole-history settle keeps. Model bug or spec gap: not yet studied.
