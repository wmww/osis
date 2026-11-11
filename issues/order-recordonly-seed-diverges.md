# held_set_decides_plain diverges at seed 562324602051 (RecordOnly)
> Summary: `order::held_set_decides_plain` with OSIS_ORDER_SEED=562324602051 fails in its RecordOnly scenario on main: two arrival orders of one held set give different state. Likely one cause with the other held_set_decides seeds (order-settings, order-partsaway, order-left-while-in-history); not yet investigated.
> Priority: normal
> Tags: tests, engine

Replay: `OSIS_ORDER_SEED=562324602051 cargo test -p osis-node --test it order::held_set_decides_plain`.
