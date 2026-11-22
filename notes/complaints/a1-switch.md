# a1-switch
> Summary: Mishaps met switching the engine to osis-perm's `paths` walk.

- The reading list (spec/permissions.md alone is 110 KB, perm-paths 56 KB) plus the engine's seam (`held.rs`, `validity.rs`) is most of a session before a line is written; the brief's "delete, then make it compile" hides that rustc reports only unresolved imports until every one is fixed, so the engine's real error count is unknown for a long while.
- `Paths` took records at construction only and numbered parts by position, both of which the engine cannot give (records arrive, a commit's edge ops resolve late): the walk needed `sync`, `add_record` and `PartKind::None` before any wiring.
