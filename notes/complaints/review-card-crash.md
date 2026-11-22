# review-card-crash
> Summary: Footguns met adding the post-rollback and set-outside checks to the engine.

- `rollback_classes` was a list that compiled but checked nothing: `accounts`, `left`, `compaction`, `epochs_judged_from`, `signing_due` sat in classes whose claim was false. A class claim needs a check that fails, or it drifts.
- A debug check that loads the store perturbs what tests count: the load shares `Core::decoded` (a decode test saw hits it did not make) and its store transaction rolls back the failed transaction's spills (a test asserted spilled rows still there). Checks keep such state aside or tests assert on counters.
- A test poking an in-memory index without its record (`derived_written`) passes every check until one compares memory with the store mid-history.
