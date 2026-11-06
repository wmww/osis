# Ephemeral reverts with restarts: two nodes end apart
> Summary: `ephemeral_reverts_with_restarts_alike_large` fails on seed 7362042 (1 of 3000 from 7360000) and seed 94 (1 of the default 200 at `OSIS_FULL=1`): a thing listed in `ephemeral_group.0~` at one node only. Cause not traced.
> Tags: ephemeral, node-sync, tests

Seed 7362042 fails in about 1.4 s, seed 94 in 1 s. At its end: the second node has role Read on the group, reads the membership and holds its entries present at no host, while the admin holds none of it. Likely reading, from that end state only (the steps were not traced): the writer was demoted, the admin and host restarted, and a reader cannot upload its copy. If so it is minor: a stale ephemeral membership at one reader until it restarts. Replay: `OSIS_EPH_START=<seed> OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6`.
