# sim crash_restart: a commit stays pending on a missing chain
> Summary: sim scenario `crash_restart` (setup 853002419338, seed 853002419342) ends not quiescent: node 1 keeps one commit pending and node 0 re-ingests `Pending(.., MissingChain(..))` every round; fails on main too.
> Priority: normal
> Tags: sim, sync, tests

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 853002419342 --setup 853002419338 --only crash_restart` (or `osis_sim::replay("crash_restart", 853002419338, 853002419342)`): `step 300: not quiescent after 50 rounds; pending per node [1, 0, 0]`. The trace repeats each round: node 0 ingests a duplicate and then a commit pending on `MissingChain` of one actor; the chain certificate it waits for never arrives. Found by the gate of the vouch trigger review; the same binary built at main fails the same way, so it predates that branch.
