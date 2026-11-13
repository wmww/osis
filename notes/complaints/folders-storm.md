# folders-storm
- known_failures and the issue named only one of the two failing `folders` seeds; the gate log naming the other (246158026007) kept its setup only in a scratchpad log (setup 246158025995). A KNOWN line should carry `setup/seed`.
- The net harness's `deleted` counter and `Kind::Commit { ais }` were what made the storms observable in a default test; finding a shape that reproduces each (a dead uncovered delta: a map key removed, not overwritten; a dropper without a delete key) took most of the time.
- The `work_sets` storm (issues/work-sets-delete-storm-194.md) is a different mechanism: one node deletes the same blob ID again and again, nobody re-encrypts it.
