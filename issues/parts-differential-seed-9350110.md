# Parts differential seed 9350110: a valid body dropped where the oracle strips it
> Summary: osis-node `parts::parts_differential_large_spec_commits_4` at offset 9350000 (150 seeds): 76 failures, the first 12 all seed 9350110, "body 04413612.. t:list.0 / t:text.0: got valid dropped, want valid stripped" in variants 0 and 3, fixed sync, as delivered and blobs come. Fails alike on 02be71d2e (before whole-2b). Not triaged.
> Tags: engine, retention, tests

Repro: `OSIS_PARTS_START=9350110 OSIS_PARTS_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact parts::parts_differential_large_spec_commits_4` (1.5 s, 28 failures). The full run's remaining 48 failures were not printed (the assert shows 12); rerun the range with a larger print to list other seeds. Found in periodic run 15 (whole tier-2 set).

Also in that run: 16 harness panics `three writes` at core/node/tests/it/order.rs:1047 (`commit_hostile(m).unwrap().expect("three writes")` returned None for a `Step::Three`), swallowed by the seed runner (it reported 0 failing seeds); a generator step the engine now refuses, worth a look at the same time.
