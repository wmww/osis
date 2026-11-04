# Ephemeral reverts with restarts: two nodes end apart
> Summary: `ephemeral_reverts_with_restarts_alike_large` fails on about 0.03% of seeds (a placement at one node only); on eph-lane (memory bodies on the durable path) 1 of 3000 seeds from 7360000, down from 6 before. Cause not found.
> Tags: ephemeral, node-sync, tests

Seed 7362042 (eph-lane): a thing listed at one node only (`placed.0~`), 3000 seeds from 7360000, 51 s. Before eph-lane the same range failed on 7360357, 7361488, 7362042, 7362228, 7362950 (a placement at one node only) and 7360445 (a value at one node only, a demoted writer the last holder after its admin and the host restarted); all but 7362042 pass now. Replay: `OSIS_EPH_START=<seed> OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6`.
