# frontier-f2 complaints
> Summary: Mishaps met building frontier-study F2.

- A role commit that lowers an edge always has a `roles.0` part no compaction snapshot covers (roster snapshots are not in `ix.snapshots` for it), so a "rotation under a role snapshot" test built from removals is listed before and after the fix and proves nothing. Pure rotations (self-removal, then `ensure_rotated` by another admin) are what the frontier rule touches. Cost one test rewrite.
- `tools/bin-at main OUT --take <test file>` was the quick way to show new tests fail on main (about 30 s per build); needs a wip commit first.
