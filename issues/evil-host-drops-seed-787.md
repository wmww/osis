# evil_host_drops: host 0's label never settles
> Summary: sim seed 472765857787 of `evil_host_drops` is not quiescent after 60 rounds at step 200 (another seed changes labels after quiescence): every extra round adds and deletes entries under one label at host s0 (content commits, snapshots and unknown blobs) while host 1 drops and garbles messages. Fails on main as on branch eph-purge (found by its gate). Not studied.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --only evil_host_drops --seeds 1 --from 472765857787` (1 s); `osis_sim::replay("evil_host_drops", 472765857787, 472765857787)` (setup: `--from`).
- Also setup 899326633465 seed 899326633475 (fails on main as on branch rotation-lows): `labels changed after quiescence (ping-pong)`, s0's label adding unknown blobs; `cargo run --bin sim-sweep -- --only evil_host_drops --seeds 1 --from 899326633475 --setup 899326633465` (7 s).
- The churn is at s0, the honest host. The evil host 1 drops messages and closes stalled connections. So some node may keep uploading and deleting at s0 as its view of host 1 flips each round.
