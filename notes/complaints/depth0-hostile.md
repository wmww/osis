# depth0-hostile
- A Depth0 instance with one extra device and one removal (`D0_fork_rm`, MaxE 9) still runs for many minutes even for invariants alone; liveness needs a stripped copy (no write). Budget model time accordingly.
- Tier 1 took ~12 min alongside two TLC runs (6 workers each): the box was shared; run TLC after tier 1 when time matters.
- `run.sh small` took 62 min: it runs one TLC worker, and `D0_fork_live` (a "small" liveness instance) alone took 26 min single-threaded under load. `TLC_WORKERS=8` would help; the "about a minute" in run.sh's header is long out of date.
- `cycle_removals_leak_nothing_random_large` at full size failed 4/200 seeds on a writer-side check this branch first dropped: the "removal without rotation" check was also what stopped `grant` from lowering an edge. A shape rule doing a second job silently; now an explicit refusal in `grant_in`.
- Review: `run.sh small` took 16 min at one worker under load with `D0_fork_live` already out; `MC_samets` (307 s), `L_list` (175 s), `D0_fork_old` (125 s) moved to `all` too.
