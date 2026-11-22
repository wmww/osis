# The order harness finds a role commit's things reached along more than one path
> Summary: osis-engine `order::held_set_decides_plain` and `_exhaustive` fail on some seeds (seed 2609037846) with "a role commit's things are reached along one path", on main's binary (e13f00b7a) as on the sibling-steps branch. Cause not read.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=2609037846 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (and `_exhaustive`; `OSIS_ORDER_SHRINK=1` shrinks). First read the check that panics (an engine debug assertion or the harness's?) and whether today's role-path changes (owner keys in roles-model, the old engine walk) make it reachable; shrink and decide which side is wrong.
