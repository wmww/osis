# A sweep over 2^18 hidden list elements writes a delta receivers refuse
> Summary: A compaction sweep's content-less list records (spec/sync.md §7) count toward `MAX_DELTA_BARE` (2^18 per writer delta, spec/crdt.md §3.3 rule 7), so a view with more hidden elements than that writes a refused delta. From reading the code, not run; needs 2^18 hidden edits between compactions.
> Priority: low
> Tags: crdt, engine

Options: split the sweep over several commits, or exempt a sweep's element resets from the cap (they are bounded by the state).
