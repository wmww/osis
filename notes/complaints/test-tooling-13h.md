# test-tooling-13h
- Editing osis-base (testenv) rebuilt the whole workspace: the first tier-1 run took 17 min at load 40-50 (build most of it). Test support living in osis-base makes every harness tweak a full rebuild; a separate test-support crate would avoid it.
- A probe of the hung-seed path with `OSIS_SEED_TIMEOUT_SECS=5` marked every seed hung: at load 35 a forked_reseals seed takes 5-10 s on 16 threads. Probe with a timeout well above a normal seed's cost.
- Review: `--ignored _large` as a filter also runs `order::*_large*` (minutes) and `ephemeral::many_authors_under_host_rates_large` (minutes at load): name each twin with `--exact`.
- Review: a hung-seed probe at `OSIS_SEED_TIMEOUT_SECS=2` with 2 threads stops dispatch after 2 hangs for good, even when one of them finishes later (the rest report "not run"); fine for a real hang, surprising in a probe.
