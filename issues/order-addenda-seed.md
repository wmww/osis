# The order harness judges an Addenda history differently by what was held
> Summary: osis-engine `order::held_set_decides_plain` fails at `OSIS_ORDER_SEED=169360654999 OSIS_ORDER_LEN=60` (an Addenda-mode history: a write, a demotion, edge writes): "histories judged differently by what was held", on main's binary (8e1faf3a6) as on the reset-redates branch. Not shrunk, cause not read.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=169360654999 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks it).
