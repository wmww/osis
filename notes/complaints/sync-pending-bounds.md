# sync-pending-bounds
- The `examined()` scale counter never counted the O(pending) skip scan in `reexamine` (records-awaiting commits were skipped before the counter), so the old cost was invisible to the counts; a drift-pending flood showed it.
- `tools/known_failures.txt` lines for `order::kill_and_purge...` and `scale::purge_rejudge...` fail here as on sync-rebuild; easy to mistake for a regression on a pending-path change.
