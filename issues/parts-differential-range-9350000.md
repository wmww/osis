# Parts differential large range: failures not listed, a generator step refused
> Summary: osis-node `parts::parts_differential_large_spec_commits_4` at offset 9350000 (150 seeds) had 76 failures; the first 12 (seed 9350110) were a harness slip, fixed; the other 64 were never printed, and `Step::Three` panics `three writes` (the engine refuses the commit) are swallowed by the seed runner.
> Tags: engine, retention, tests

Seed 9350110 (fixed): an expiring two-part commit whose cut parts arrived before the commit could apply waited past T and went as never received (spec/commits.md §5, the aspect flagged `PendingExpiry`); the harness left out the flagged aspect's own line but compared its bodies' lines (`body <commit> <tid> <ak>`: dropped here, stripped where the commit came whole). It now leaves those out too.

Left: rerun `OSIS_PARTS_START=9350000 OSIS_PARTS_SEEDS=150` with every failure printed (the assert shows 12) and triage what is left. Also 16 harness panics `three writes` at core/node/tests/it/order.rs (`commit_hostile(m).unwrap().expect("three writes")` returned None for a `Step::Three`), reported as 0 failing seeds: a generator step the engine now refuses.
