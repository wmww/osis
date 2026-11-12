# A sweep over 2^18 hidden sequence elements fails, and the snapshot with it
> Summary: A compaction sweep's content-less sequence records (list element resets, text deletes, spec/sync.md §7) count toward `MAX_DELTA_BARE` (2^18 per writer delta, spec/crdt.md §3.3 rule 7). The writer's own encoder refuses more (`Enc::note_bare`), so the sweep commit errors and `write_snapshot` fails with it on every try: the aspect is never compacted. From reading the code, not run; needs 2^18 hidden elements between compactions (e.g. undeletes of a large text concurrent with its replace, over several commits).
> Priority: low
> Tags: crdt, engine

Options: split the sweep over several commits, or exempt a sweep's element resets from the cap (they are bounded by the state).
