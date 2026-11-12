# Churn seed 634611312032: one node's map lacks a key the other reads
> Summary: `random_churn_converges_large` seed 634611312032 (a gate's 20 from 634611312021) does not converge: node 1 reads the map without key `a__I7_gU0szD-rcgunFO` (`v28`) that node 0 has; fails alike on main effab1c91. Cause not traced.
> Priority: normal
> Tags: ephemeral, engine, tests

Replay: `OSIS_EPH_START=634611312032 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large` (a few seconds). Panic at `core/node/tests/it/ephemeral.rs` (the convergence check): `node 1 reads Some(Map({k1: v35, k2: v56, 2bGnYYmFsAeuJk-C0C3i: v54})) Some(Str("f45")), node 0 Some(Map({..., a__I7_gU0szD-rcgunFO: v28}))`. A different failure from issues/churn-cursor-rebuild-differs.md (no rebuild check fires): a durable write lost at one reader, so data loss until shown otherwise.
