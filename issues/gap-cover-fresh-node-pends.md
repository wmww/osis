# A fresh node filled from a dropper can stay pending
> Summary: `sessions::gap_cover_large` seed 737100473 fails on main: a fresh node given all of a node's packages after it dropped covered bodies pends on `WaitDeltas`. 1 seed in 1000; not looked into.
> Tags: engine, retention, tests

Replay: `OSIS_GAPCOVER_START=737100473 OSIS_GAPCOVER_SEEDS=1 cargo test -p osis-node --test it -- --ignored sessions::gap_cover_large`. Message: `the fresh node pends: [(CommitId(45b33145c3d00096..), WaitDeltas)]`. It fails the same at origin/main 87e40f0b, before join-cost. First find which body the waiting commit needs and why its coverer does not stand in for it (spec/commits.md §4, §5).
