# sim revoke_while_writing: an addendum written does not count where written
> Summary: sim scenario `revoke_while_writing` (seed 887135679473) panics at step 0 on the debug check in `flows::addenda` (`an addendum written here does not count here`): right after writing an addendum, the node's own `owed` still owes it on the same thing; fails on main.
> Priority: normal
> Tags: engine, sim, tests

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 887135679473 --only revoke_while_writing` (or `osis_sim::replay("revoke_while_writing", 887135679473)`): `panic: an addendum written here does not count here: CommitId(efeae142..) on [Tid(..)]`. One seed of the gate's 15 for that scenario. Found by the a2-spec review's gate (whose code changes outside the unused evidence derivation were comments); main's binary fails the same way.
