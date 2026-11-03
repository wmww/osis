# idle-trigger
- `honest_flows_wait_for_no_resync` stops at its first failing seed and prints blob IDs, which say nothing across two runs. A sweep needs one process per seed and a trace (`OSIS_TRACE_UPLOADS`) to name what differs.
- `OSIS_TRACE_UPLOADS` prints no deletes and no time; a probe had to add both.
- A foreground oracle run was moved to the background at 180 s: use `run_in_background` from the start.
