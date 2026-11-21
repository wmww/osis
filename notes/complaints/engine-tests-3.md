# engine-tests-3
> Summary: Footguns met while hunting retention plants and cutting engine default-test cost.

- A test's comment claimed a state it never reached: `shred::purge_of_a_part_waiting_aside_reads_alike` said a part waits aside, yet nothing ever pended (the setup it was written for, a node not syncing a thing, went with the closure rework). A test claiming a wait should assert the wait (`pending()` names it), or it silently tests something else.
- `recoverable` (the forensic attack) sees nothing of a pending copy on a thing outside the node closure, value or not: a "no copy left" check there passes vacuously. Assert the value is recoverable before the step that should remove it.
- A pinned seed hid a failure: `seq_cold_edits_keep_placement` on seeds 187/189 passed, every other seed tried fails.
- Debug-build `Backtrace::force_capture` in a mutate probe printed no frame names; counting `PROBE` lines per caller site was what worked.
