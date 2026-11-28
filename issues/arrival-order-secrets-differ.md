# A removed reader's held secrets depend on arrival order
> Summary: engine `rotation::tests::arrival_order_holds_alike_large_spec_permissions_3` fails on main at `OSIS_ARRIVAL_START=62853083563 OSIS_ARRIVAL_SEEDS=1`: node N (not a reader, "N in false") holds other secrets in one delivery order than in order, so what N keeps of a thing's role secrets depends on arrival order (spec/permissions.md §3 No secret taken back).
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ARRIVAL_START=62853083563 OSIS_ARRIVAL_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests::arrival_order_holds_alike_large_spec_permissions_3` (order 1 differs: "N holds otherwise than in order"). Not probed; it fails with or without the local part's chain-cut rule (spec/sync-set.md §2 The local part's log). Next: a hand-written reproducer of the order that differs.
