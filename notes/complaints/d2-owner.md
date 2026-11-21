# Complaints: d2-owner
> Summary: Workflow snags met modelling owner keys in roles-model `paths` (stage D2).

- `Thing` is a `u8`, so keys sharing its numbers (from 0x80) cap things at 127; a cost test that minted things 30..130 had to move down. A wider `Thing` would reach osis-perm's and held-model's `tid` conversions.
- A `tools/heavy` started before an edit builds the tree as it is when cargo runs, not when the call was made: a property run queued while editing may test half the change. Wip-commit, then start it.
- A mutation batch under `MUTATE_HEAVY=1` waits between plants on every other agent's hold (13 min for 12 plants of a 20 CPU-s test); the short lane would fit each plant, but mutate.py takes the full lock.
- A clause inside `if ... { } else { EXPR }` cannot be planted by mutate.py (the wrapper is not a block): write such a rule as one expression (`a || b`) before mutating it.
- `each_fix_is_needed_plain` asserted the `-leave` control fails within 100 story worlds; two new thief moves redrew every world and it failed none of those 100 (48 checks in 400). A control asserted at a fixed small size is a rate: size it with a margin when it is written.
