# random_window_inflight seed 3300065 diverges
> Summary: `ephemeral::random_window_inflight_large` seed 3300065 (cap 4000 at the first of two servers) ends with node 0 lacking writes of nodes 1 and 2 that only the uncapped second server holds: node 0's lane shows nothing present at server 2. Fails on main's engine too (found in the eph-unpaged-cover review); cause not looked into.
> Tags: ephemeral, node, tests

- Repro: `OSIS_EPH_START=3300065 OSIS_EPH_SEEDS=1 cargo test --workspace --test it ephemeral::random_window_inflight_large -- --ignored`.
- Node 0 (group owner, restarted twice) reads `k3=v2` where the others read `k0=v12, k3=v15`; the missing commits (`623a..` by node 1, `abef..` by node 2, node 0's own earlier-session `10af..`) are present only at server 2 and were refused by the capped server 1 (`capped [1]` at the holders). Node 0's own cover and a presence entry are its only entries, both present at server 1 alone: it looks as if node 0 never reopened the label at server 2 after a restart or a block, rather than a cap question (with two servers the check does not excuse cap refusals, and need not: every node is on both).
- The other 299 seeds of 3300000..3300300 and both other variants passed.
