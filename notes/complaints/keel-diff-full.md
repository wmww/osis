# keel-diff-full
- A batch of split runs that names `target/debug/deps/it-*` picks up a rebuild mid-batch: copy the binary to the scratch dir first and run the copy. `ls -t deps/it-*` picks another crate's `it`.
- The seed "hang" (seed 5) was a slow loop with no checkpoint: 22 deliveries per turn, so neither the settle guard nor the storm cap fired within the 600 s seed timeout. `OSIS_SYNC_TRACE=all` then counting `+entry` per (node, S) found it in minutes; worth a line in notes/sync-test-harness.md if it recurs.
- `OSIS_SYNC_TRACE=<nodes>:step` matches every line with "Step" in it (path steps), not only script steps.
- A full-size shrink is 10-20 min single-threaded; run several seeds' shrinks in parallel, unlocked.
