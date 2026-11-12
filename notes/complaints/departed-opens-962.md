# departed-opens-962
> Summary: Workflow notes from triaging rotation seed 962141499239.

- A replay piped through `tail` reports exit 0 on a failed seed; the issue's replay line is easy to misread that way. Capture to a file and read `test result`.
- The failing-history log names peers by index but `check`'s data by Tid; mapping them took an ad hoc eprintln probe. A peer/actor legend line with Tids in the log would save that step.
- Review: three heavy-lock waits (925, 931, 432 s) were most of the review's wall time; a rebase onto a landed branch (rotation-lows) conflicted twice on append-only logs (known_failures, time-limits Hits).
