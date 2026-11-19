# gimbal-unit-rollback
> Summary: Docs-only branch told to delete notes and issues that code comments cite, keep tools/policy.py passing, and touch no code: the three cannot all hold.

- Deleting notes/sync-unit-design.md and three issues leaves six code-comment pointers (core/sync/tests/it/idle.rs, core/test/held-model) that tools/policy.py rejects; a docs-only brief that deletes cited files needs the code owner's comment fix in the same merge. Worth a check in the brief: grep code for the files to be deleted before scoping a branch docs-only.
- The brief's S1 figures (310-370 and 234-437 store rows per sync ID) predate main's S1 fixes; idle.rs's counts are what holds.
