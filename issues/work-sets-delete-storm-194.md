# work_sets: host s1 deletes one commit's blobs over and over
> Summary: sim `work_sets` setup 43254590189 seed 43254590194 fails on main at step 160: "message storm: 5000 deliveries", s1 deleting the same content blobs of one commit (parts [0, 1], `s:hi.0` + `s:reg.0`) under one label again and again. Possibly the cause of issues/folders-sim-message-storm.md (s0 deleting one commit's blobs under two labels); not studied.
> Priority: normal
> Tags: sync, sim

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 43254590194 --setup 43254590189 --only work_sets` (5 s).
