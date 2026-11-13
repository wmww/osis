# seq-paste-order
- A by-hand 20,000-seed sweep of `fuzz_seq::random_scripts_replay_spec_5_7` (one process per seed, 0.28 CPU-s each, from a copied binary) ran at 1.5x the `heavy` limits at load 33; no per-test seed range (`_START`/`_SEEDS`) exists for it, so a sweep spawns 20,000 processes.
- `Placement::index` (via `Lin::index`) finds only a row's first dot; nothing says so at the call sites that pass any dot (paste's clipboard).
