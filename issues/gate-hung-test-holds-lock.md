# A hung test holds the gate and the heavy lock until someone notices
> Summary: `tools/gate.sh` has no per-test hang limit: a livelocked default test (osis `sharing::leave_of_a_links_maker_gives_up_the_link` once) kept a gate and the box-wide heavy lock for about 70 minutes, every other agent queued, the only sign libtest's "running for over 60 seconds". sim-sweep already bounds a run.
> Priority: normal
> Tags: tests, tools

- Fix: the gate kills a test target whose output shows no test finishing for a multiple of the `test` limit (notes/time-limits.md) and reports the running tests as NEW, "hung" (the failure classification then treats it like any failure). Check what at 0 and infinity (notes/arbitrary-values.md): the multiple bounds a hang, not a slow test, which the limits already report.
