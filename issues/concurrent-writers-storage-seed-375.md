# concurrent_writers seed 375 stores over its bound
> Summary: sim-sweep `concurrent_writers` setup 892962858361 seed 892962858375 ends with node 0 storing 399,650 B against a bound of 399,408 B (must hold 97,304 B in 52 entries under 2 labels): 242 B over. Fails alike on main at 11e6a92f0; not triaged.
> Priority: normal
> Tags: tests, sim, storage

- Replay: `cargo run --bin sim-sweep -- --seeds 1 --from 892962858375 --setup 892962858361 --only concurrent_writers` (2 s).
- Start at: what node 0 holds beyond the must-hold set (an uncompacted aspect or a kept superseded body) and whether the bound's slack or the store is wrong; so small an overrun suggests one extra body or a snapshot not yet taken.
