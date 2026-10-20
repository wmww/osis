# Sim sweep residues at 200 seeds: link_race and evil_server
> Summary: The final 200-seed release sweep of every scenario (7400 runs) fails 5 seeds: `link_race` 91, 119, 164, 191 and `evil_server` 134; every other scenario is green at 200 seeds. Not pinned down; replay calls below.
> Tags: sync, permissions, sim, tests

Repro (release): `osis_sim::replay("link_race", 91)` (also 119, 164, 191), `osis_sim::replay("evil_server", 134)`; `cargo run --release -p osis-sim --bin sim-sweep -- --seeds 200 --budget-secs 3000` reproduces the counts (elapsed ~40 min on 4 cores).

Context: `link_race` races two redemptions of a single-use link while the sharer finalizes; earlier residues of this scenario were a stranded winner (fixed: rotations reach unboxed members by inbox) and an unpromoted deposit (fixed: server-confirmed promotions). `evil_server` holds back and replays its own messages; 199 of 200 seeds converge.

Next: replay each seed with `OSIS_SIM_TRACE=1`, classify (liveness stall vs wrong state), fix in node-sync or flows, extend the sweep to 10^4 seeds per the nightly job (`.github/workflows/nightly.yml`).
