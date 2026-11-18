# Strip and delete rules no test catches
> Summary: Two delete rules survive their plants: a part dropped as covered strips under no purge on replace, and a certificate or record blob deleted by levels with no basis; each needs a small test that fails without it.
> Priority: low
> Tags: tests, sync, engine

- `strips` (engine/src/sync/bodies.rs): a part dropped as covered strips only where its aspect is under purge on replace. Planted to strip under any history: no osis-sync `it` or engine lib test fails. `deletes::a_reader_receives_a_part_whose_cover_was_covered_whole_*` names it, but the reader counts a stripped part covered through its cover's cover, so it reads alike. The observable loss is history: a reader of an aspect keeping history should still fetch the replaced version from a store. A plain own replace in `sync::tests_facts` keeps the body (not dropped as covered), so an engine test needs the compaction that drops it.
- `cert_delete_basis` (sync/src/read/live.rs `delete_item`): a writer's Delete by levels of a certificate or record blob. Planted to `None`: no osis-sync `it` test fails (the delete-key path is `keep::a_delete_key_holder_never_deletes_*`).
