# Tell a deleted thing from one never written
> Summary: `knows(t)` means "has content", so a thing never written and a deleted one read the same (`state empty` in the CLI). Telling them apart takes an engine marker: states are pruned, and `changed` loses the delete in a compaction snapshot.
> Tags: api, engine

Nothing today depends on the difference. If an app needs it, deletion gets a marker the engine can read (notes/api.md "deletion is derived, never a flag" says it has none), and `has_content` splits into a three-valued read. Rejected from the API layer alone: a delete is a change, so `changed != created` looks like the marker, but a change known only from a snapshot is not seen, so a new device would read a deleted thing as never written and say so with confidence.

Related: a purge writes `purge.0`, which counts as content, so a thing whose only register was purged reads `knows == true` with nothing to show. Fix with this: `core_types::is_content` also decides what `delete` removes.
