# held_set_decides: a settled node shows `t:docs.0` other than the node keeping every body
> Summary: engine property `order::held_set_decides_plain` fails at a rate on main: one 60-step history, settled, reads `t:docs.0` on one thing differently from the node that kept every body (Settled check); seen at seed 182803249374, on main's binary as on the A1 step 1 branch.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=182803249374 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (fails on origin/main f96be0a4f's binary, `tools/bin-at`); `OSIS_ORDER_SHRINK=1` shrinks it. The panic: `held [all 211] of 211 commits (base 48), order #7 [...]: now, settled: shows other than the node keeping every body: <tid> t:docs.0`. The history mixes compactions (`Compact` on t1), purge sets, forged commits, leaves and an undo. Not yet shrunk or read: the minimal reproducer is the fix's first step (notes/principles.md, Never pin a seed).
