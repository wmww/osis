# rotation-class-2
- Bisecting a property seed across merges needs the harness of one commit over the engine of another; the generator's rng use drifts, so "passes at X" can mean "not reached at X". Here the current harness compiled at every bisect point, which kept the replays comparable.
- testenv rejects unknown env vars (core/base/testenv-known.txt), so an ad hoc debug toggle in a property run panics until named in the list; reusing an existing name or a plain eprintln is quicker.
- A passing test hides its eprintln output; tracing a passing seed needs `--nocapture`.
- The asked-for 2000-seed `rotation_holds_large` run hit the `heavy` limit (CPU 6424/5060 s, wall 641/598 s, load 18): the limit is sized for a smaller by-hand run, not a task-requested 2000 seeds.
