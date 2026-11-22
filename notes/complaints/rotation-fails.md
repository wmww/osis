# rotation-fails
- `tools/heavy --short` refused a one-seed property replay (8 CPU-s) because the same command line once ran full-size (366 CPU-s): the lane keys on argv, not env, so every `OSIS_ROTATION_START=… SEEDS=1` replay waits on the heavy lock behind gates.
- A bisect across two days rebuilt the engine lib tests from cold at each step (5-10 min each, plus lock waits); the issues' suspects list (today's commits) was wrong for every seed: these seeds come from rolling offsets and had failed since the generator reached their shape.
- The property's failing-history log names peers and actors by index but prints tids elsewhere; mapping them by hand was the slowest part of reading each failure.
