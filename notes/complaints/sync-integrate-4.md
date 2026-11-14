# sync-integrate-4 complaints
- A pattern `sed '/DBG/d'` over core/ to drop my own debug prints also removed another branch's `eprintln!("DBG ...` lines (engine sessions.rs), leaving an unused variable that only clippy caught. Remove debug prints by file, never by a repo-wide pattern.
- Debug prints greped with `grep "seal"` hid the engine's own "DBG section" lines: a probe's tag should be one unique word per site.
- The differential costs ten times its budget once content flows (issues/sync-test-cost.md): a 100-seed default run of the two convergence tests is 2,400 CPU-s, so seed sweeps had to go through `OSIS_SYNC_SEEDS` by hand.
- Engine tests `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` and `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6` fail on sync-rebuild itself (checked with `tools/bin-at sync-rebuild`), not from this branch.
- `git rebase sync-rebuild` re-applied the facade's commits (sync-rebuild does not hold them yet), so its conflicts were the facade's against the prose pass and durable records, not this branch's.
