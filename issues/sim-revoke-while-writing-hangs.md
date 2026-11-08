# sim `revoke_while_writing` runs without end at some seeds
> Summary: seeds 215135495581 and 215135495588 of sim scenario `revoke_while_writing` run past 90 s (others take under 1 s; one unbounded sweep ran 28 min) on main's engine at b2623eda5 too. sim-sweep has no per-seed timeout, so such a seed stalls a sweep silently. Not looked into.
> Priority: normal
> Tags: tests, sim

Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 215135495581 --jobs 1 --only revoke_while_writing`. Unknown whether it is a livelock in the scenario's driver or a real non-converging sync. sim-sweep's `--budget-secs` only stops starting seeds; a per-seed timeout that reports the seed as failed would turn a hang into a finding.
