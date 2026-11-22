# a1-walk
> Summary: Mishaps met rebuilding osis-perm's `paths` walk.

- The brief's reading list (redesign-plan, write-path-design, a1-spec, spec, roles-model `paths`) is about 300 KB before any code: most of a session's context. A1's rules are in spec/permissions.md §5.1 and roles-model `walk`; a brief naming those two alone would do.
- `core/perm/tests/it/paths/content.rs` grouped a two-thing commit's parts in the old walk's order (by thing first), not spec §5.1 step 1's; it surfaced only as a differential failure ("model Unapplied, walk Applied").
- notes/redesign-plan.md said both "the key hop always listed until A4 brings list writes" and (issues/perm-walk-trails-model.md) "the rebuilt walk with owner keys; the skip goes": the brief did not say which.
