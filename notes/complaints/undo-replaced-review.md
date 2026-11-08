# undo-replaced review
- A first `cargo test` run logged to a scratchpad subdirectory that did not exist yet: the redirect failed, cargo never ran, and the background task still reported exit 0 (the `echo` after it). Create the log dir first and read the log, not the task's exit code.
- A one-test filter in osis-node still costs about 3-4 min of build after an engine edit.
