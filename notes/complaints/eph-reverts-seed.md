# eph-reverts-seed
> Summary: footguns met tracing the eph-reverts seed.

- Tracing a node-sync property seed needs throwaway eprintlns in src: test output is captured on pass, so a "fixed" run prints nothing; grep only on failing runs.
- `net.demote` + `carry_out` + `net.run()` does not finish a demotion: the harness's `advance(15_000)` after it is load-bearing (a regression test without it silently checks nothing).
- The memory reconcile after a fallen snapshot waited for `resync_ms` (60 s), longer than most tests advance, so the gap hid behind timing.
