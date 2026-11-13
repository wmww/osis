# purge_tombstones: node 1 commits on a thing it may not write
> Summary: sim `purge_tombstones` setup 647906408026 seed 647906408031 fails at step 220 with "node 1 commit: no permission to write" (after a restart of node 1 and several "delete refused: code 1" diagnostics). Fails on main's engine alike (found by the churn-884 gate). Not studied; maybe the same class as issues/member-churn-write-without-access.md.
> Priority: normal
> Tags: tests, sim

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 647906408031 --setup 647906408026 --only purge_tombstones` (seconds).
- Next: find whether the sim picks a writer the scenario demoted, or node 1 loses write it should keep.
