# crdt-tests-move
> Summary: workflow snags met moving osis-crdt's lib tests to tests/it.

- Comparing before/after builds in one worktree costs a full workspace rebuild per switch (4-5 min): changing crdt's pub surface rewrites its metadata, so every dependent recompiles. A second worktree for the "before" side would have been cheaper but doubles target dirs.
- Box load moved 6 to 24 during the runs; single build timings are only good to about 2x. Repeat each edit and quote ranges.
- Lib-test cost hides `cfg(test)` behaviour in the library (`LIN_MIN = if cfg!(test)`, test-only asserts and probes): a test move surfaces them as failures, not compile errors.
