# held_set_decides_plain: a body leaves at its row while still in history
> Summary: `OSIS_ORDER_SEED=458968566698 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main (Settings emphasis) on `retention::leaving`'s debug check: a `t:reg.0` body leaves at its row (`leaving.rs`, "left at row ... while in history") though a fresh `replaced_at` keeps it in history. A leaving row set too early under some order or clock, or the check's fresh date wrong; shrink with `OSIS_ORDER_SHRINK=1`. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, engine, retention
