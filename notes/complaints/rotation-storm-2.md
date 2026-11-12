# rotation-storm-2
> Summary: Workflow notes from the roster-merger branch.
- Measuring a sim seed's per-actor epochs needed a throwaway probe in the scenario (no report field counts role commits or epochs per actor); a `Report` count of rotation commits per actor would make storm checks one command.
- A first `Merge.tla` instance at four nodes with liveness grew past 2M states in 8 min (held subsets per node); three nodes check liveness in a second, four only invariants.
- `heavy` serializes even one-worker TLC runs: a 1 s model waited 196 s behind another agent's hold.
