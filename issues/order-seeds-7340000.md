# Two order seeds fail on main too
> Summary: Fresh-offset seeds found in the members-cost review, failing the same without that branch (837fce32): `new_device_alike` 7340054 (a compaction by a writer against an invalid body: `every body` {} vs `after covered drops` {k0: ...}), `arrival_order_alike` 7340007 (a map entry as a plain struct vs as slots after a held prefix). Not triaged: may share causes with the other order issues.
> Tags: tests, engine
Replay: `OSIS_ORDER_SEED=7340054 cargo test --workspace --test it order::new_device_alike_large_spec_permissions_5_1 -- --ignored --exact`; `OSIS_ORDER_SEED=7340007 OSIS_ORDER_LEN=60 ... order::arrival_order_alike_large_spec_permissions_5_2`. Each shrinks by itself.
