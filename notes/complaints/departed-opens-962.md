# departed-opens-962
> Summary: Workflow notes from triaging rotation seed 962141499239.

- A replay piped through `tail` reports exit 0 on a failed seed; the issue's replay line is easy to misread that way. Capture to a file and read `test result`.
- The failing-history log names peers by index but `check`'s data by Tid; mapping them took an ad hoc eprintln probe. A peer/actor legend line with Tids in the log would save that step.
