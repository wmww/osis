# reupload-loop
- `OSIS_SIM_TRACE=1` prints wire messages only; a loop's cause (which judgment says upload, which says delete) needed temporary `eprintln!`s in `pass/bodies.rs` and `pass/delete.rs` keyed on a commit ID. A per-node "why must-hold / why deletable" trace keyed by commit would save this each time.
- The seed-2 shape (an own replace dropped at one node under a pair one of which later fell, gone from the host) has no small network reproducer; only the engine semantics test and the sim seed cover the per-delta liveness fix.
- Review: making an own replace fall in an engine test is hard: a purge strips it (held as leftover) and expiry keeps it as an expired leftover, so neither reaches `uncover`; only a validity flip (demotion with a frontier short of it) did.
- Review: issues/eph-churn-delete-upload-loop.md's repro passes on main; an issue's replay line goes stale silently.
