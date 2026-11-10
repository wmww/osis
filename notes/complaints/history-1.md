# history-1 complaints
- A generator change (new rng draws) turned up an arrival-order failure unrelated to the change: `props::settle` never fetched again a part thrown out as unknown from a commit still waiting on a parked part. Any held-model generator change is effectively a new seed range; budget for an unrelated find.
- Measuring the adapter's coverage against main meant swapping main's files into the worktree behind a wip commit and rebuilding osis-node's test binary twice (about 3 min each).
- `held_model::*` and `crdt_model::state::*` both export short names (`Entry`); a new held-model type named `Entry` broke every test file's glob imports.
