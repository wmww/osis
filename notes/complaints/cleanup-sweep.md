# cleanup-sweep
- An osis-level test cannot see a parked commit stay pending: node sync's `sweep_pending` drops any row no label entry carries, so a commit fed by `engine(|e| e.ingest(..))` is gone by the next settle. Tests of pending state belong at the node level with a carrier.
- Diagnostics are deduped in `Events` by (kind, commit, tids), so a "told once" test passes even without the engine's own once-check; it cannot tell the two apart.
- Item 3's rename edited osis sources while item 2's test run was in flight in the same worktree; separate the work by commit order, not by editing during a run.
