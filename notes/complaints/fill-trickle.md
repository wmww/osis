# fill-trickle
- `fill::no_pass_before_order_0_at_two_hosts_spec_sync_6` passes with the `fill_first_waits` gate removed (on main too): only the one-host case has teeth.
- The issue's fix had two halves; the first (a fill's batch stale past the stall time) made the second (keep skipped bodies queued) unobservable in the sim, where an honest host answers in zero time: tested each half disabled before settling on one.
- (review) That test's stranded check has no teeth at either size: `read_first` keeps a node holding no head epoch from stranded while the rotation is asked, gate or not. What the gate stops is a pass asking every unopened entry at once in ID order; the test now checks messages come newest first, which fails at both sizes without the gate.
