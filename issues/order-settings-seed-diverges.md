# held_set_decides_plain: a Settings history read differently at an earlier clock
> Summary: `OSIS_ORDER_SEED=28067082 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main (and on ended-keyed): with all 75 commits held, order #0 at an earlier clock (`at: 70`) reads a thing's aspect as `Map({0: "v6"})` where the expected read is `None` (Settings emphasis: settings, a `PurgeSet`). What is read depends on the clock a node took the commits at; shrink with `OSIS_ORDER_SHRINK=1`.
> Priority: normal
> Tags: tests, engine, retention
