# keel-checks-every-size
- A mutate.py run holds the worktree's test binaries for its whole run (tens of minutes for 4 mutations over the engine tests): no build in that worktree meanwhile, so a second base worktree was the only way to compare old and new detection in parallel.
- Moving the index check to each engine's drop surfaced three test-harness gaps the sampling hid: a lib test editing `ix.secrets` without `index_poked`, crash tests dropping an engine over a dead store, and engines dropped mid-load (a failed open). Each needed its own skip in the drop.
- A check comparing a derived index at drop time against a rebuild must pin the clock to the last transaction: tests advance a shared ManualClock without ticking every peer.
