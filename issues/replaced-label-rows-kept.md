# A node keeps its hub rows of a label it no longer syncs
> Summary: Once a node stops syncing a label without forgetting its group (a replaced label: a non-admin at once, an admin once retired), its hub's rows of it stay for good, and the `n` flag keeps the label node sync's (`HostStore::reads`), so it is neither served as a sync ID kept unread nor dropped.
> Priority: low
> Tags: sync, host, node-sync

- Seen in node `destruction::a_release_requests_entry_goes_where_it_is_held_unread_*`: after a replacement, every node (writer and admin) still holds its rows of the old label `ROLE_KEEP` later (the role-class commits kept there).
- Expiring rows still go (node sync expires every entry it derived, notes/node-sync.md Expiry), so only rows without an expiry stay: bounded by what the node held of the label, per replaced label.
- `n` is cleared only by `reader_forget` (the group forgotten). `set_read` dropping a label leaves it.
- Fix direction: when node sync stops syncing a label, its rows there either go (forgotten, as `reader_forget`) or turn unread (`n` cleared, host rules from then on). Which one depends on whether the node still serves the old label to stale readers (spec/sync.md §2, replacement).
