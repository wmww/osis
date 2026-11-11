# held_set_decides_plain: a PartsAway history read differently at an earlier clock
> Summary: `OSIS_ORDER_SEED=458968566693 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main (PartsAway emphasis): with 49 of 65 commits held, order #0 at an earlier clock (`at: 31`) reads an aspect as `Map({0: "v0"})` where the expected read is `None`. Same shape as issues/order-settings-seed-diverges.md (what is read depends on the clock the commits were taken at), another emphasis; shrink with `OSIS_ORDER_SHRINK=1`. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, engine, retention
