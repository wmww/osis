# pending-bound
- The issue text predated expiry-6 (unjudgeable commits are thrown out), so its main example (an author's record that never comes) no longer pends; the open hole was the other pending kinds (`Epoch`, `WaitBlobs`, `Drift`, `Parked`) outliving their entries and escaping the unvouched bounds once opened. Reading which pending kinds still store bytes took most of the time.
- A group's own label is its inbox, so `unvouched_cap` there is a sixteenth: a test cap of 8 means 0 at the label. Easy to miss when writing a cap test.
- `net.diagnostics` dedups the sync engine's strings against the event detail, so a helper pushing a prefixed string into `diagnostics` shows the same report twice.
- Review: a test that a carrier keeps a pending row passes vacuously unless the commit's other routes are cut (a reader places a holder's keys under the group's label over its peer link too); check it fails with the carrier disabled.
- Review gate: stopped on the known order::held_set_decides_plain floor; gate.hold wall 282 s > 177 s at load 26 (busy box); sim-sweep run by hand, green.
