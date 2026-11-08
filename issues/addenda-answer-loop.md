# A node spins forever answering removals with addenda
> Summary: sim `revoke_while_writing` seeds 63306707752 and 63306707753 never finish (other seeds take 1 s): the node loops in `Engine::package` -> `flows::addenda::answer_removals` -> `commit_in`, writing and applying commits on every packaging call. Hangs `sim-sweep` and `work_sets::work_sets_match_full_passes` (no per-seed timeout there). Still hangs on 8f3cd8d05.
> Priority: normal
> Tags: engine, node, tests

Found by the periodic run (main e3cdd005f): two sweep threads ran past the budget for over an hour, and the tier-2 `osis-sim` binary hung on the same two seeds in `work_sets_match_full_passes` (`OSIS_SIM_FROM=63306707746`). Replay (runs until killed): `cargo run --bin sim-sweep -- --seeds 1 --from 63306707752 --only revoke_while_writing`.

Profile of 2 min of the hang (a SIGPROF sampler, tools/cpuprof): 95% under `Sim::missing` -> `Engine::package` -> `Engine::commit_bytes` -> `addenda::answer_removals` -> `write::commit_in` -> `apply_local` (half in `validity::rejudge_all` / `Judge::vouching`, a quarter in `check_rebuilt`). So packaging a commit writes an answer commit, and the loop does not reach a fixpoint: either each answer creates a new removal to answer, or the "already answered" check misses the answer just written. A single seed has no trace output until it ends, so the next step is a step counter or `OSIS_SIM_TRACE` lines flushed as they happen.

Also worth a line in the tooling: sim-sweep and the `work_sets` comparison have no per-seed CPU limit like the seed runner's `OSIS_SEED_TIMEOUT_SECS`, so a livelocked seed hangs a whole periodic run and names no seed.
