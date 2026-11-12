# snapshot_rights: a content commit's copy re-placed and deleted forever
> Summary: sim `snapshot_rights` setup 896215582406 seed 896215582419 ends in a message storm (on main alike): node 2 places a copy of a content commit (`Content` on `s:map.0` and `s:reg.0` of one thing) under the label, node 1 fetches it and deletes it, node 2 places a new copy (fresh blob ID) at once. The same loop as issues/work-sets-snapshot-storm.md, there on a `ContentSnapshot`; likely one cause. Not studied.
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 896215582419 --setup 896215582406 --only snapshot_rights`; `OSIS_SIM_TRACE=1` shows node 2's `Stream L+X L-W`, node 1's `Fetch X` then `Delete X`, round after round. Nodes 1 and 2 print `delete refused: code 1` earlier in the run.
- Also setup 913562411000 seed 913562411001 (storm on `s:reg.0`/`s:count.0` content, node s0 deleting each fresh copy).
- Start at: why node 1 judges the copy must-not-hold while node 2 re-places it (spec/sync.md §6 verdicts), as in the work_sets issue.
- Also sim `team_reads_member_thing` setup 72407225782 seed 72407225794 (on main alike): message storm at step 160, node 0 deleting and re-adding `Content` copies of two commits of one thing under two labels. Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 72407225794 --setup 72407225782 --only team_reads_member_thing`.
- Also `snapshot_rights` setup 731400 seed 731412 (on main alike): storm at step 40, host s0 deleting copies of one `Content` commit on `s:reg.0` and `s:count.0`. Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 731412 --setup 731400 --only snapshot_rights`.
