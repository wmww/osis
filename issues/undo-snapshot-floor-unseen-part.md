# A kept snapshot excuses parts its writer never saw
> Summary: `undo::replaced_kept` stops at the newest kept whole part and excuses every part stamped before it. A reset or register write supersedes all of those by stamp, but a compaction snapshot holds only what its writer had applied: an unkept part stamped earlier and unseen by the snapshot's writer is excused, so an undo of a later write that removed it writes back less than the state before.
> Priority: normal
> Tags: engine, undo

Construction (map aspect, `keep_history(1d)`): B writes entry `k` untyped (no history) at ts 10 and stays offline; C writes a compaction snapshot at ts 20 without it; B syncs to A; A removes `k` at ts 30 (kept). A's undo of the removal: the walk meets the snapshot (kept, whole), stops, passes; `kept_before` holds the snapshot and no `k`, so the removal is undone without `k` coming back. Same with main's rule (the undone write's own retention), so not a regression of `replaced_kept`.

Fix direction: a snapshot excuses only the parts its `Frontiers`/`Absorbed` reach (`retention::snapshot::unseen_by` already reads them; `Indexes::snapshots` holds them per aspect); a part it does not list is judged on its own (conservative: one whose writes all died before the snapshot is not listed either). Older snapshot parts need a rule too (their content is copies of deltas, each judged by header).
