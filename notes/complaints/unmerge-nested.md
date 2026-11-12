# unmerge-nested
- A first Net reproducer wrote B's commit at the same manual-clock instant as A's demotion, so the commit was valid and the test passed for the wrong reason. Advance the clock between a removal and a write meant to land after it.
- A `tools/heavy ... > dir/file` run fails at once if the scratch directory does not exist yet; the background task still reports exit 0 ("done").
