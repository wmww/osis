# held_set_decides_plain: held-model applies a role commit the node does not
> Summary: `OSIS_ORDER_SEED=833299603861 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` fails on main (PartsAway): a partial held set, reversed at an earlier clock, after 30 ingests (the clock moved): held-model differs: commit #55 (not in the held set; two `roles.0` parts, one on a thing whose record the node does not hold, `first admin None`) applied: model true, node false. Engine (unjudgeable commit thrown out, spec/commits.md §4 Unjudgeable) or held-model's input (what the node's role input holds of an unheld commit) disagrees; not yet looked at.
> Priority: normal
> Tags: tests, engine, held-model

Replay as in the summary; `OSIS_ORDER_DUMP=1` prints the index differences, `OSIS_ORDER_SHRINK=1` shrinks it (slow; it may settle on another failure).
