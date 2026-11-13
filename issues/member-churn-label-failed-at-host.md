# member_churn: a label stays Failed at a host at quiescence
> Summary: sim `member_churn` setup 921485473073 seed 921485473124 fails at step 151: node 2's label b6e1af25.. of group LBhI6MHy.. is `Failed { entry_refused: false }` on its connection to host 0 at quiescence (no key opens it there) while the sim expects it open. Fails on main 65bdadb74 alike.
> Priority: normal
> Tags: sync, sim, tests

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 921485473124 --setup 921485473073 --only member_churn` (`osis_sim::replay("member_churn", 921485473073, 921485473124)`). Also setup 127881523466 seed 127881523480 (step 148, label df103951.. `Failed` at host 0; fails on main 65bdadb74 alike). And setup 913370 seed 913414 (step 145, `Failed` at host 0 after two nodes' "step refused (code 9)"; fails on main 65bdadb74 alike).

State at the failure: conn 4 to host 0, the other label 49ad4043.. `Open { by: Some(..), doubted: None }` and a member of the shared set; b6e1af25.. `Failed`, head step 249 known there, `synced false`, nothing outstanding. Early trace: a partition N(4) | S(0) and a cut link 2 around steps 17-26, then `node 2 diagnostic: delete refused: code 1`.

Not looked at: whether node 2 lacks every credential of the host's head (then the sim's expectation is wrong for this history, or a re-seal is missing), or a Failed label is never tested again after a later head or key arrives (spec/sync.md §5: a failed label keeps testing its credentials). Property to name first: "a node holding a credential of the peer's head opens L there".
