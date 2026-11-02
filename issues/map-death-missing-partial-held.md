# A map write's death undated at a partial held set
> Summary: order seed 57309, one partial held set: a `t:map.0` body has no death where the oracle dates one (`death dated early or missing`, as made, not a snapshot's copies as in issues/map-snapshot-death-missing.md, so that skip does not catch it). It fails the same on main without split delivery, so parts waiting alone did not cause it. Undiagnosed.
> Tags: tests, retention, engine

Repro: `OSIS_ORDER_SEED=57309 OSIS_ORDER_LEN=60 cargo test --workspace --test it order::arrival_order_alike_large_spec_permissions_5_2 -- --include-ignored` (about 1.5 min: it shrinks).
