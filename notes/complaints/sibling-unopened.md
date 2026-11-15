# sibling-unopened
> Summary: workflow notes from the sibling-removal diagnosis.

- gdb could not attach to a running test binary (ptrace refused): a slow-but-moving run (a merge war at one world ms) looked like a hang; OSIS_SYNC_TRACE on the run showed it, a new commit per delivery.
- `w.cap` bounds deliveries, but a war where each delivery costs more than the last takes minutes to reach a cap of 6 000: the test-thread "running for over 60 seconds" line is the only sign.
