# A nested map entry's value-less writes differ by arrival order, parts withheld
> Summary: order seeds 83009 and 83043 (`Syncs::Late`, parts withheld for good): one order's `t:map.0` state holds a nested struct entry's value-less fields, the other's lacks them. 83043 fails alike on main's code under the new harness, so sync timing is not the cause. The shape looks like the un-merge of nested writes in issues/new-device-alike-nested.md; re-run once map-snapshots merges, and close if gone.
> Tags: tests, engine

Repro: `OSIS_ORDER_SEED=83043 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (add `OSIS_SHRINK=0` to skip shrinking). Shrunk histories hold `Demote` and `Nested { compact: true, also: true }`.
