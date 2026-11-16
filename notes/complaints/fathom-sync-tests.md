# fathom-sync-tests
- issues/sync-tests-owed.md pointed at `1dcacb6b0` for the old issues, an object that does not exist; they are at `e1bafb8ca^` (two under their `label` names). Fixed the pointer.
- Several owed items name old-sync mechanisms (hub rows, `relink_pending`, `peer_received`) with no counterpart in the rebuilt sync; mapping each to a rebuilt rule takes reading the old issue and the new module notes first.
- A per-process `--exact` run of one sync test rebuilds its cached fixtures (2-4 s for a `contacts`-based test); the in-process cost is a third of that.
