# reupload-loop
- `OSIS_SIM_TRACE=1` prints wire messages only; a loop's cause (which judgment says upload, which says delete) needed temporary `eprintln!`s in `pass/bodies.rs` and `pass/delete.rs` keyed on a commit ID. A per-node "why must-hold / why deletable" trace keyed by commit would save this each time.
- The seed-2 shape (an own replace dropped at one node under a pair one of which later fell, gone from the host) has no small network reproducer; only the engine semantics test and the sim seed cover the per-delta liveness fix.
