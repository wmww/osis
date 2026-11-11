# held_set_decides_plain: a Lists history read differently by arrival order
> Summary: `OSIS_ORDER_SEED=438123470748 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main (Lists emphasis): orders read a Lists history differently. Order independence of what is read is broken somewhere in engine judging; shrink with `OSIS_ORDER_SHRINK=1`. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, engine
