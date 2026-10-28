# snapshot-authority
- Box load 90+ from other projects: tier 1 took 8 min instead of under 1; the order oracle 3.5 min.
- Test trap: `lp.sync_all()` after pushing an extra peer gives it every commit, so a "Dave holds only the snapshot" test passed vacuously until checked with an assertion that Bob's commit is not held. Push the extra peer after the last sync and assert what it lacks.
- The order harness reports only the first differing part (index before states): a liveness row differed when the cause was a state difference; reordering `judged` locally showed it.
- `runtime::close_while_driver_runs_no_timer_panic` failed once in tier 1 (known flaky, issues/close-timer-panic-flaky.md).
