# mizzen-prose-tests
- Test deletions left the notes citing what was gone: the held-set `quick` size (f856fedff) and osis-sync's `metadata.rs`/`shred.rs` (e499872aa, not listed as owed either). A commit that deletes or renames a test should `rg` notes/ and issues/ for its name.
- A word-list check (every backticked identifier in a note against `rg -o` over the code) found these in seconds; a per-name `rg` over the tree was too slow.
