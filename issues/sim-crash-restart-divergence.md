# crash_restart seed 623023: two nodes hold the same commits and read a set differently
> Summary: `osis_sim::replay("crash_restart", 623023)` fails on main and on partial-fetch alike: nodes 0 and 1 hold the same commits but `s:tags.0` reads {birch, cedar} at one and {birch} at the other, at step 300. Not looked into beyond that.
> Tags: tests, engine, node-sync

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 623023 --only crash_restart`. At the failure node 1 lists commit 7f05b85's delta on the aspect as `missing` while applied, the others hold it: a crash lost or split that part. First step: which crash, and why nothing brought it back.
