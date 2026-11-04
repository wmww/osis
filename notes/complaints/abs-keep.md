# abs-keep complaints
> Summary: footguns met on the absolute keep-at-most branch.

- A failing order seed's shrink ran 650 s on one thread inside a tier-1 module run (`partial_roster_snapshot_removes_nobody_seed_3050`), with nothing printed until it ended; `OSIS_ORDER_SHRINK=0` gave the diff in 36 s. A tier-1 run could default to no shrink.
- `Engine::tick` alone drops a live body with no carrier (node-sync writes carriers in `run_engine_timers`); tests calling `net.engine(n).tick()` on a sync node model nothing real. `SyncEngine::expire_due` is the offline-node equivalent.
- The order harness's random `op` draws feed pinned explicit histories and judgment vectors: changing what an existing op writes silently changes those regressions. New behaviour goes in new op numbers.
- Oracle set ran at load 60 (other agents' runs): about 3x the testing.md wall times.
- Review: keep-at-most and expiry timers share one key per (time, commit, part); a death-set keep-at-most timer at T == expiry overwrote the expiry's kind, so an expiring live entry outlived its expiry (now never set there).
- Review gate 692 s at load 35-85 (other agents' runs); the alike oracle at 5317000 ran 222 s, its one seed's shrink 107 s.
