# whole-3 complaints
> Summary: Mishaps and slow spots met building whole-commits step 3 (apply never waits for a part).

- The step's spec text carried a rule ("sealed sections of things not synced stay unopened") that cannot be judged at open time: a commit placing a new thing in a synced group carries the thing's record in a section the receiver does not know it syncs yet. Found only by tracing the open path; a design note naming where each rule is judged would have shown it.
- Test docs restate the rule they test in prose ("counts as held", "waits whole"), so a rule change leaves dozens of passing tests with false comments; grep for the old wording was the only way to find them.
- `set_syncing` used to re-examine pending commits; dropping that changed the timing of a parked part's expiry in one test (it relied on the sync toggle as its tick).
- Review: a definition living inside a deleted clause ("could hold the right", in §4's Purged) stayed cited from spec/sync.md §6; `spec_map` does not catch a dangling definition. A `pub` counter (`Held::edges`) outlived its only reader with no warning.
