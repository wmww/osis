# sim folders: message storm deleting the same blobs

> Summary: `sim-sweep` scenario `folders`, setup 636429852973 seed 636429852979, fails on main at step 100: `message storm: 5000 deliveries without the queue emptying`, the trace showing s0 deleting the same blobs of one commit under two labels over and over. Not looked into.
> Priority: normal
> Tags: tests, sim

Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 636429852979 --setup 636429852973 --only folders` (5 s), or `osis_sim::replay("folders", 636429852973, 636429852979)`. One of 15 seeds.
