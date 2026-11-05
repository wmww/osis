# Forged walks seed 9374128: open and rebuilt Carried index differ
> Summary: osis-node `walks::open_equals_rebuild_random_histories_forged_large` seed 9374128 (1 of 200 from 9374000): at the end, peer 2's open and rebuilt indexes disagree on `Carried(813ad27a..)`: "want <none>, got" a carry of `t:gonemap.0` counters 1..60 from one source. States equal. Fails alike on 02be71d2e (before whole-2b). Not triaged.
> Tags: engine, tests

Repro: `OSIS_WALKS_FORGED_START=9374128 OSIS_WALKS_FORGED_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact walks::open_equals_rebuild_random_histories_forged_large` (0.2 s). Found in periodic run 15 (whole tier-2 set). Incremental-vs-rebuild index drift (cf. item 147): a stale carriers row after a forged commit's part is dropped or turns invalid.
