# A node keeps its hub rows of a label it no longer syncs
> Summary: Once a node stops syncing a label without forgetting its group (handed off), its hub's rows of it stay for good, and the `n` flag keeps the label node sync's (`HostStore::reads`), so it is neither served as a sync ID kept unread nor dropped.
> Priority: low
> Tags: sync, host, node-sync

- Shown by node `destruction::a_release_requests_entry_goes_where_it_is_held_unread_*`: a node that handed a group off still holds its rows of the group's label.
- Expiring rows still go (node sync expires every entry it derived, notes/node-sync.md Expiry), so only rows without an expiry stay: bounded by what the node held of the label.
- `n` is cleared only by `reader_forget` (the group forgotten). `set_read` dropping a label leaves it.
- Fix direction: when node sync stops syncing a label, its rows there either go (forgotten, as `reader_forget`) or turn unread (`n` cleared, host rules from then on).
