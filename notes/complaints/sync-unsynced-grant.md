# sync-unsynced-grant
> Summary: workflow notes from fixing the differential's unknown-outcome grant.

- The differential's failure print says "refused" for a write whose outcome is unknown, which reads as "had no effect": it hid that the grant stood and only the oracle's bookkeeping (no accept filed) was off. A probe of `Engine::store_writes().unknown` after the step settled it in one run.
- osis-engine's order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5 and scale::purge_rejudge_is_linear_in_requests_spec_permissions_6 still fail on sync-rebuild (known); this branch does not touch the engine.
