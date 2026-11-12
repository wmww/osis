# A runtime test's wait_synced gives up under load
> Summary: osis `runtime::a_paired_peer_serves_what_it_reads_in_process_spec_data_model_9` fails now and then in the gate at load 20-26 (`wait_synced` returns `Unsynced` for the new group at runtime.rs:695) and passes alone, on main too: a wall-clock bound in a default test.
> Priority: low
> Tags: tests, node

- Seen in gates of chunk-list-in-tree and net-3i (load 26); three runs alone pass in 1.4 s.
- Fix: find which wait inside `wait_synced` is bounded by wall time (a back-off or settle timer on the real clock) and drive it by events or a guard far above the box's worst load, as notes/testing.md asks of default tests (no wall-time asserts).
