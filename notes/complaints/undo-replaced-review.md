# undo-replaced review
- A first `cargo test` run logged to a scratchpad subdirectory that did not exist yet: the redirect failed, cargo never ran, and the background task still reported exit 0 (the `echo` after it). Create the log dir first and read the log, not the task's exit code.
- A one-test filter in osis-node still costs about 3-4 min of build after an engine edit.
- `serving::stop_serving_erases_its_store_spec_data_model_9` failed once in the gate (a label left after stop, serving.rs:453), then passed 5 runs alone and the next gate: a load-dependent flake (issues/serving-stop-erase-flaky.md).
