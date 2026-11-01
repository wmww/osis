# test-tooling-13h
- Editing osis-base (testenv) rebuilt the whole workspace: the first tier-1 run took 17 min at load 40-50 (build most of it). Test support living in osis-base makes every harness tweak a full rebuild; a separate test-support crate would avoid it.
- A probe of the hung-seed path with `OSIS_SEED_TIMEOUT_SECS=5` marked every seed hung: at load 35 a forked_reseals seed takes 5-10 s on 16 threads. Probe with a timeout well above a normal seed's cost.
