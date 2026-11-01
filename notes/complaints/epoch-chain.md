# epoch-chain
- Issue repro seeds go stale: own-rotation-invalidated named seed 23, which no longer reproduced (the test's own-epoch skip also hid it); a 400-seed scan of the old code with the skip turned into an assertion found 34 failing seeds (25 the first). Before trusting a seed from an issue, re-run it on main.
- `forks_with_departures_settle_large` stops at the first failing seed, so finding every failure in a range means one process per seed (a copied test binary under `xargs -P`): 400 seeds took about 8 min at 12 jobs under the nice-19 periodic run.
- Each seed of that harness is 2-4 s in dev, so a tier-1 test per seed is the most that fits "a few seconds each".
- Review: `PROPTEST_CASES` from `.cargo/config.toml` (32) overrides a test's own `proptest_config` `cases`, so an in-code `cases: 2048` runs 32 and a "60000 cases" probe finished in 0.00 s. Pass `PROPTEST_CASES=N` on the command line for a deep run.
- Review: `forks_with_departures_settle_large` at 200 seeds runs single-process for many minutes with no per-seed progress line; one `--nocapture` run tells nothing until the end.
