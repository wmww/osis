# gap_snapshots_converge: states differ at 11 of 300 seeds
> Summary: osis-node `waits::gap_snapshots_converge_large_spec_crdt_8` at `OSIS_ORDER_START=9344000` (300 seeds): 11 fail, "Ak(t:gonemap.0 | t:big.0) states differ, 0 ms on" between the gap-holding and the whole peer (seeds 9344001, 016, 037, 076, 125, 156, 204, 206, 244, 275, 296). Fails alike on 02be71d2e (before whole-2b). Not triaged.
> Tags: engine, crdt, tests

Repro: `OSIS_ORDER_START=9344001 OSIS_ORDER_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact waits::gap_snapshots_converge_large_spec_crdt_8` (1 s). Found in periodic run 15 (whole tier-2 set). The harness reads `OSIS_ORDER_START`, so it only moves off its default range when the order offset does: these may be old failures no run reached before. The diff is in map entries' register writes (print both states fully to see which entry).
