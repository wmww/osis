# one-peer-3c
- Building a crate (`cargo build -p osis-node`) while a `cargo test -p ... -p osis` run was still going made the osis doctests fail with E0460 ("found possibly newer version of crate"): the run had built its rlibs, then the doctests linked against the newer ones. Don't build in the worktree while its test run is still going.
- Five harnesses drive a `Hub` (node driver, sim `World`, sim `net`, osis-node `Net`, osis-host `World`); a new `HubOutput` or `Action` variant touches all five.
