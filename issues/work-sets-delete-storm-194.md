# work_sets: host s1 deletes one commit's blobs over and over
> Summary: sim `work_sets` setup 43254590189 seed 43254590194 fails on main at step 160: "message storm: 5000 deliveries", s1 deleting the same content blobs of one commit (parts [0, 1], `s:hi.0` + `s:reg.0`) under one label again and again. Possibly the cause of issues/folders-sim-message-storm.md (s0 deleting one commit's blobs under two labels); not studied.
> Priority: normal
> Tags: sync, sim

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 43254590194 --setup 43254590189 --only work_sets` (5 s).
- Same storm in `member_churn` setup 720956814942 seed 720956814950, on main too (step 56: s0 deleting and re-adding one content commit's chunk blobs, `s:reg.0`): `cargo run --bin sim-sweep -- --seeds 1 --from 720956814950 --setup 720956814942 --only member_churn` (5 s).
