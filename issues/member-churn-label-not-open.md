# member_churn: a label never opens at a host
> Summary: sim `member_churn` setup 211283068035 seed 211283068035 fails on main: node 2's connection to host 0 keeps a group's label Testing (head None, synced false) at quiescence. Not studied.
> Priority: normal
> Tags: sync, sim, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 211283068035 --setup 211283068035 --only member_churn` (fails at step 148); `OSIS_SIM_TRACE=1` for the trace.
- Start at: why the node never registers or opens that label there (a step refused for now and not registered again, or a head it never read).
