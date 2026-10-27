# Index rebuild loses a held snapshot of a keep-at-most aspect
> Summary: Order harness seed 1291 (outside the tier-2 range): after a rebuild of the persisted index, a compaction snapshot of an at-most-0 aspect is missing from `Core::snapshots`; the incremental index has it.
> Tags: node, tests

Repro: `OSIS_ORDER_SEED=1291 cargo test --workspace --test it order::arrival_order_alike_large -- --ignored` (fails on main too).
History: `vec![Write { by: 0, t: 2, op: 18, k: 2, v: 3 }, Compact { by: 0, t: 3, op: 18 }, Demote { by: 0, t: 3, member: 1, at: 3, to_read: false }, Undo { by: 0, back: 2 }]`. The diff: `snapshots` of `/t/gone` holds one entry (frontier of one node, counter 1) incrementally, none after `rebuild_index`. Likely the open's rebuild skips snapshots whose part was dropped or does not examine (`apply::load`, `examine_stored`), while the incremental path kept the entry (or the reverse). Seen with `OSIS_ORDER_SEEDS=300`: the only failure among seeds 1000-1299.
