# A runtime test's wait_synced gives up under load
> Summary: osis `runtime::a_paired_peer_serves_what_it_reads_in_process_spec_data_model_9` and `runtime::redeem_in_process_spec_permissions_7` fail now and then at load 20-26 (`wait_synced` returns `Unsynced` for the new group) and pass alone (about 1.4 s): a wall-clock bound in a default test. Listed in tools/known_failures.txt.
> Priority: low
> Tags: tests, osis

Find which wait inside `wait_synced` is bounded by wall time (a back-off or settle timer on the real clock) and drive it by events or a guard far above the box's worst load, as notes/testing.md asks of default tests (no wall-time asserts).
