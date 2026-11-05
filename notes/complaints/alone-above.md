# alone-above
> Summary: workflow notes from the alone-above branch (blocked through holder actors).

- `core/test/tla/run.sh small Depth0` matches nothing silently: the filter is on `dir/cfg` (use `D0_`).
- Depth0 liveness instances spend most of their epochs bound on forks: two admins both rotating for one removal fork the actor, and the merge needs one more epoch; a MaxE one short shows up as a `Settles` counterexample stuttering at the bound, which reads like a real lockout until you count epochs.
- Liveness checking in Depth0 is slow per state (the closure operators are re-evaluated per state); safety-only runs of the same instance are about 10x faster.
