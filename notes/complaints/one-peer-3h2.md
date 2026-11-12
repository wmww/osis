# one-peer-3h2
> Summary: Workflow notes from the 3h2 worker (pull, one pass).

- The step is far larger than one worker session: pull, one pass, deposits, the walk replacing Open, eight new tests, and about 90 osis-node tests written around uploads, Status and Budget codes (`lose_uploads`, `uploaded`, hostile puts racing an upload). A brief that split 3h2 into pull plus one pass, then the walk, then the test rewrite would have fit.
- Three osis-node tests hang when the change is wrong (`deposit_queue::queued_deposit_after_seed_refresh_spec_sync_5`, two `destruction::`), and libtest has no per-test timeout: the whole run then waits until killed by hand, and no panic message prints. A run that kills at the stall and prints the panics so far would save a rerun.
- Debug output in a test needs `--nocapture` and an env var guard can't be set from a test (`unsafe` is forbidden), so a probe meant editing library code each time.
- Two groups created back to back in a test can share a label ID (`sync_review::self_removals_drop_per_group_spec_permissions_3`); a fresh session does not expect that.
