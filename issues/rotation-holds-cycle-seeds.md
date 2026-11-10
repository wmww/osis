# rotation_holds: two cycle-emphasis seeds fail (a leak, a refused re-seal)

> Summary: `rotation_holds_large_spec_crypto_4` at small size from offset 3141590000 fails at seeds 3141590091 (a removed peer opens the Read epoch the first admin encrypts under) and 3141590047 (settle's `reseal_due` returns `Permission` for a peer `role_now` gives a role). Both are holder-actor (cycle) seeds; not root-caused.
> Priority: normal
> Tags: security, engine, keys, tests

Replay: `OSIS_ROTATION_START=<seed> OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4`.
- 3141590091: `peer 1 (now None) opens Tid(..) Read epoch n4 .. peer 0 (Admin) encrypts under` (the leak check in `check`). Check first whether it is the stated limit of issues/sealer-cannot-judge-holder.md; if so the property's allowance is missing it, else an engine leak.
- 3141590047: `reseal_due(..).unwrap()` in `settle` panics with `Permission { tid }`: a node judged to hold a role on the actor is refused a re-seal of it.
Both are new mechanisms in the rotation area after its class study (notes/coordination.md, Seed chases): take them as one study of holder-actor judging, not two patches.
