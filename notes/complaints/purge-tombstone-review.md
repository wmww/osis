# purge-tombstone-review
> Summary: Mishaps met reviewing purge-tombstone.

- Picked local record prefix `y/`: node-sync's state keeps its records under `y/`, invisibly to engine `records.rs`, and a stray key fails a load only for some commit IDs (16 of 40 runs). Prefixes in `records.rs` should list or reserve what other crates use.
- `at_host` reads a node's own entries: during an upload war the same blob is present and absent by turns, which looked like "no entry anywhere"; print the state's entries before trusting it.
- A fix-disabled probe with `git checkout <file>` undid an uncommitted fix (coordination's footgun 2): caught by a grep, re-applied.
