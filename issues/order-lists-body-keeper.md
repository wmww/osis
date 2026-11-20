# order: after the sync exchange a node shows other than the node keeping every body (Lists)
> Summary: osis-engine `order::held_set_decides_plain` at seed 647344785572 (Lists, OSIS_ORDER_LEN=60) fails "now, after the sync exchange: shows other than the node keeping every body" on a `text.0` value (want "v0", got "v0x"). Fails on main's binary.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=647344785572 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (fails within 10 s; `OSIS_ORDER_SHRINK=1` shrinks it). The history has a big demote, a leave, undos and mixed commits; one held order of 101 commits (base 48) reads a write ("v0x") the node keeping every body does not show.

Next: shrink it, then find which body-keeping or listing rule lets the write stand at one node and not the other.
