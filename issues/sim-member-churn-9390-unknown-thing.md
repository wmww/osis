# Sim member_churn seed 9390: a scenario commit on an unknown thing
> Summary: `member_churn` seed 9390 fails at step 113: "node 5 commit: unknown thing 6ZlFObgFEUKGRpzl5rl8". Fails on main at 768707845 as well (not from 2b-regress). Not triaged.
> Tags: sim

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 9390 --only member_churn --jobs 1` (or `osis_sim::replay("member_churn", 9390)`). Found by the 2b-regress sweep (`--seeds 30 --from 9370 --only snapshot_rights,revocation_bob,member_churn`, the only failure of 90).
