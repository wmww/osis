# A `label.0` may name a label its group does not own
> Summary: Nothing checks that a label a group's `label.0` records derives from that group's secrets, so an admin of t can list u's label in t's `label.0`; honest nodes syncing both then hold one label under two groups, and once t is destroyed and emptied they run `empty_pass` and `labels_emptied` on u's live label.
> Priority: low
> Tags: security, node-sync, engine

- `compute_synced` lists `(t, l)` and `(u, l)`; the passes run once per pair, so l gets a `label_pass` for u and, once t keeps nothing (`Engine::emptying`), an `empty_pass` for t.
- `empty_pass` drops this node's entries of l no source holds (its own unplaced ones included); it deletes nothing at a host (t's secrets derive no key of u's steps, `head_keys`), so `end_emptying` finds no key and calls `labels_emptied` at once: `SyncRecords::forget` drops l's sync records and sessions, and the node syncs l again from scratch for u.
- A label ID derives from its genesis delete key (spec/sync.md §2), which only an admin of the owner derives; a sync-or-above holder can still check that some step's sync key derives from the group's sync secret. A fix: drop, when reading `label.0` (`labels_read`, `group_labels_in`), a label none of whose steps' sync keys the node derives from the group's epochs, or reject such a `label.0` write as invalid; then the destroyed case needs nothing of its own.
