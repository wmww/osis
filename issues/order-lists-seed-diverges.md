# held_set_decides_plain: a Lists history read differently by arrival order
> Summary: `OSIS_ORDER_SEED=632724249436 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main d45be663a: with every commit held, order #3 reads `Some("m1")` where the others read `None` (Lists emphasis). Order independence of what is read is broken somewhere in engine judging; shrink with `OSIS_ORDER_SHRINK=1`.
> Priority: normal
> Tags: tests, engine

Also `OSIS_ORDER_SEED=325201414215` (the gate's offset 325201414214, branch touching only net tests): order #1 at an earlier clock, after the sync exchange, reads `roles.0` of one thing as `None` where the node keeping every body reads an edge map.
