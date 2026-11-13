# history-cut-2 complaints
> Summary: Workflow snags met while adding the hostile writer to Cut.tla.

- The brief's "about 10 minutes" per TLA run is far above the `heavy` hold limits on fastbox-0 (wall 439 s, CPU 3718 s: about 230 s wall at 16 workers). Caps I set from the brief hit them twice (`X_host` sized blind: 661 s and 10,212 CPU-s; then 421 s and 6,510 CPU-s, both unfinished). State the hold limit in the TLA guidance (notes/testing.md, notes/coordination.md) instead of a minute count.
- An attacker that picks any listing and floor multiplies the state space by the subsets of known epochs times the floors: size such instances from a one-worker probe first (one hostile rotation, `MaxC` 5-6), never by adding a second actor blind.
- The same instance's time swings with box load near the hold limit (`X_later` 181 s, then over 226 s unfinished at load 20): leave a 30% margin.
- `run.sh` still uses `mktemp -d` (tmpfs) for its metadir; by-hand runs here used a directory under the worktree's `target/`.
