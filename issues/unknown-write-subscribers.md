# Subscribers miss a commit that landed after answering Err
> Summary: When a store write's outcome is unknown (a failed sync), the engine reloads in place (`Engine::load` from `run`, `Writes::unknown`) and may find a commit it answered `Err` landed after all (e.g. a shredding commit whose last batch failed after its root record). The reload sends no event, so `osis` subscriptions (event-driven, watch.rs) keep showing the state without it until something else touches those aspects or the app restarts. Pull reads are right (`point()` moves).
> Priority: normal
> Tags: engine, osis

Data on disk and engine reads agree; only push deliveries are stale. Fix candidates: diff commit IDs before and after the in-place load and queue `Changed` (and roster/groups/commits events) for the newly present commits' aspects; or one "everything may have changed" message that makes `osis` re-deliver every subscription (brute force is fine: the path is rare). Test: node `crash::a_failed_sync_at_any_write_of_a_purging_commit_needs_no_restart`'s setup with a subscription on the purged aspect.
