# Ephemeral reverts with restarts: two nodes end apart
> Summary: `ephemeral_reverts_with_restarts_alike_large` fails on about 0.2% of seeds (a placement or a value at one node only), with kept rows off too; main before kept rows failed 2% of the same seeds. Cause not found.
> Tags: ephemeral, node-sync, tests

Seeds 7360357, 7361488, 7362042, 7362228, 7362950: a thing listed at one node only (`placed.0~`). 7360445: a value at one node only, a demoted writer the last holder after its admin and the host restarted (perhaps a reader's stale stamp refused 9, spec/sync.md §6). 3000 seeds from 7360000, 96 s. Replay: `OSIS_EPH_START=<seed> OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6`.
