# keep-simple
- The two known engine failures (`order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5`, `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6`) still fail on sync-rebuild; easy to mistake for one's own.
- No admin issues steps in the product, so the removal end-to-end test calls `Engine::issue_step` by hand; until steps are issued, a removed node keeping S unread keeps its copy in the product.
