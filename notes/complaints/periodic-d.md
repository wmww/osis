# periodic-d
- `tied::grant_and_removal_orders_large` had a fixed 0..40: no fresh range possible. It now takes `OSIS_TIED_START`/`_SEEDS`. Other fixed-range large tests may remain.
- `work_sets_match_full_passes` passing hides `parted:` lines (stdout, captured): read them with `--nocapture`. A clean `1 passed` said nothing about 7 parted runs.
- Main moved mid-run: the sweep's 5 snapshot_rights seeds were fixed by d55 while the run went on. Fetch before writing up a failure.
- Costs this box, nice 19: sim sweep 150 seeds 667-817 s (the documented 50 min is stale), work sets 20 seeds 156-216 s (notes/testing.md says 19-28 min elsewhere).
- Disk: 38 G free to 22 G over the session, mostly not this worktree (12 G target).
