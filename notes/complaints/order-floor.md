# order-floor
- A by-hand sampler of 200 `held_set_decides_plain` offsets as 207 seeds judged once each, floors checked over every sliding window of 8 (a scratch test, not committed), ran 470-580 s under `tools/heavy` and tripped its CPU limit (6854-7670 s against 5060 s): expected for a one-off sample, not a slow test. 200 separate runs would have cost about 8 times as much.
- The first sample run passed without `--nocapture`, so libtest swallowed its eprintln report: 8 minutes of every core lost. A by-hand run that reports through stderr needs `--nocapture`.
