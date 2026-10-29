# commit-query
- The crdt reference model had no undo at all, though the brief assumed one to update; a model undo plus differential was written from the spec by a second agent in the same worktree (its half-edited test file broke `osis-crdt` test builds for me a few times).
- `undo_restores_spec_4_6` passed with and without the exact-undo rule: random single-writer histories almost never leave a spot absent; explicit tests were needed.
- The first "Absent before" wording (reset whenever the buffer is absent there) would have let a revert of an old first write wipe later seen changes; the oracle and the osis tests caught three refinements (only value-carrying writes and `W` block, deleted seq creations do not, only the outermost spot).
