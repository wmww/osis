# Carrier and purge re-snapshot stall where no writer knows the schema
> Summary: `Engine::snapshot` returns `None` for a typed aspect whose schema the node does not know (spec/commits.md §5). `snapshot_first` (node-sync: a must-delete body with live writes and no carrier, the purge re-snapshot and keep-at-most `due_live_drops`) then writes nothing and the body waits (`Fate::Wait`). If no writer of the aspect knows the schema (the typed writers gone, the rest write untyped through the CLI), a purged body stays at servers indefinitely.
> Tags: security, engine, retention, node-sync

Before snapshot-bounds-purge such a node snapshotted with no bounds (a keep-at-most aspect's content then outlived its bound in that snapshot); now it keeps the body instead. Both over-retain; which is worse is a design call.

Option: a node without the schema takes the bounds from the held typed deltas' own header retention (each delta carries `retention`; the newest typed delta's is the schema's default unless the write overrode it). Spec §5 says a commit's own bounds never carry to a snapshot, so this needs a spec rule (e.g. the strictest at-most among held typed deltas).

Also: the snapshot's bounds come from whichever known schema declares the AK, at the revision known here, not the `(schema ID, revision)` the held deltas name; a newer revision with different default retention snapshots with the old bounds until registered.
