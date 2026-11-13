# Sim ephemeral: a refreshed cursor never read after write failures
> Summary: sim `ephemeral` setup 141303463146, seeds 141303463147, 141303463149, 141303463154 fail on main (8fb2f9402) and on net-3i3b alike: "node 3 does not read node 2's refreshed cursor cNN on D8jv… (refresh 0)" at step 300.
> Priority: normal
> Tags: ephemeral, sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 141303463147 --setup 141303463146 --only ephemeral` (also `--from 141303463149`, `--from 141303463154`).
- The runs before the check have nodes and hosts with injected store faults ("will Fail at its write 0", crashes, restarts) and partitions; not traced which node lost the cursor or where (a failed write's in-place restart of node sync, a host crash, the refresh's push).
