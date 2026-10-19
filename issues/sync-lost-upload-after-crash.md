# A must-hold body is never re-uploaded after a wipe and crashes
> Summary: In `server_loses_data` (server wiped, nodes crashing mid-write) a writer ends judging a body must-hold while the server lacks it: the writer still lists entries of that commit (not live at the server, not tombstoned) and uploads none of them. Both failing seeds had a crash inside the sync-state write (`sync state: store: storage crashed`) after the wipe; likely a presence or cursor record that survives the crash claims the entry is at the server. Not yet pinned down.
> Tags: sync, node, store, tests

- Seen in the simulator (release sweep): `osis_sim::replay("server_loses_data", 32)` (writer node 1 lacks `[(2, 0)]` of a commit with five known entries, none live) and `osis_sim::replay("server_loses_data", 41)` (one entry, not live, not tombstoned); regression test `server_loses_data_seed_41`.
- Next step: expose per-server presence (`SyncState` `is_present`) to the simulator's failure detail, or check after restart that presence records whose server log ID changed are cleared.
