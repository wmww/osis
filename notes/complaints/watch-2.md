# watch-2 complaints
- A coverage floor's per-seed spread is invisible: the old asserts printed only the sum, so choosing a rate that holds for one seed needed a temporary per-seed dump. `reach_floor` now prints the least a seed gave.
- Two floors passed every default run and failed at offsets (`purge_by_id` 0 of 2 seeds, rotation's invalid rotations 6 of 100 under a 1-in-8 rate): floors set from the default seeds alone are guesses.
- The tools' own tests ran one after another in the gate (83 s wall at load 18 for about 60 CPU-s), so `gate.checks` wall tracked their sum.
- Timing the tool tests at load 15-45 swings wall 2-4x between runs; only CPU-s compare.
