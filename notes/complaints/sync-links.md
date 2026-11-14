# sync-links
- The register task was fixed on sync-rebuild by a parallel branch mid-task; my fix conflicted and was dropped in the rebase. Two agents briefed on one walk path: lost time.
- `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` and `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6` fail on sync-rebuild's engine as is (not this branch).
- Engine ingest throws `Awaits` commits out silently (`pending()` empty, commit not held): finding why a pulled commit "opened" but never applied took a probe by hand.
