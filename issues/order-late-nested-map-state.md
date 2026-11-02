# A nested map entry's value-less writes differ by arrival order, parts withheld
> Summary: order seed 83009 (parts withheld for good): one order's `t:map.0` state holds a nested struct entry's value-less fields (stamped past an `Advance`), the other's lacks them. With syncs off and the same withheld parts it fails alike on main's code (same shrunk history, same state difference), after map-snapshots too: nothing of the sync set, the unit wait or the creation record's rule. 83043 went with map-snapshots. On main under `Syncs::Late` this seed fails first on a `created.0` body, the hole this harness change's branch closed, which hides it.
> Tags: tests, engine

Repro: `OSIS_ORDER_SEED=83009 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (add `OSIS_SHRINK=0` to skip shrinking). Shrunk history holds `Nested`, `NestedItem { compact: true, also: true }`, `Demote` and a long `Advance`.
