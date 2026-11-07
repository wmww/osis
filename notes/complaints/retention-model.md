# retention-model
- held-model's random properties hid two shapes at 300 seeds (a cover chasing itself at seed 360, a covered body keeping a purged copy at seed 655): found only at 2400 seeds, 40 s. Worth raising `SEEDS` whenever the model's rules change, not only the generator.
- The order harness's `compare` stops at the first difference, so surveying an engine that fails by design needed a process-wide `held::SURVEY` flag and an ignored test run alone; a per-`Cfg` field would be cleaner but `compare` has no `Cfg` in reach.
- The sync TLA `none.cfg` instance (two writers, two covers, time 0..1, two workers) runs for well over ten minutes where the old `timed.cfg` took 33 at one worker; "small" is relative.
