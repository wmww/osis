# blob-wait
> Summary: Mishaps met fixing blob waits (keyed by blob, walks kept incrementally).

- A first build of `osis-engine --tests` in a fresh worktree took about 6 minutes; every later lib-test rebuild about 2.5. Edits to `tests_paged.rs` rebuild the whole lib test binary.
- `unpend` then `pend_aside` in one transaction (an applied commit whose parts still wait) made "drop on unpend" lose the waiting part's walk: anything kept beside `pending` must settle at the transaction's end, as `carriers::settle` does.
