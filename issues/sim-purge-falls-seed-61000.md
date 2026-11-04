# Sim: purge_falls fails at seed 61000
> Summary: `purge_falls` and `purge_falls_churn` fail at seed 61000 with "the purge never reached the writer" (core/test/sim/src/net/library.rs), on main at 202147da too. Not looked into: a real bug or a scenario that settles too early.
> Tags: tests, sim

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 61000 --only purge_falls,purge_falls_churn`, or `osis_sim::replay("purge_falls", 61000)`. Seeds 61001..61019 pass.
