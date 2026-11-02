# parts-seeds-review2
> Summary: Mishaps on the second parts-seeds review.

- `examine` stops at the first wait, so a probe of `waits_without_expired` must leave Y unsynced: my first junk probe synced Y, went down the `Exam::Pending` path and looked clean.
- `forensic` reads every row ever written, so it can't show a row removed: a live check of `j/` needed a new test accessor (`stripped_count`).
