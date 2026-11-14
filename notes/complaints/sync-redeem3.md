# sync-redeem3
- `git apply --3way` stages what it applies, so a later `git checkout .` leaves those edits in place; reset the index first (`git reset -q`).
- sync-rebuild at f3f6f4ea1 fails two osis-engine tests unrelated to links: `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5`, `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6`.
- A sync bug that ends in an engine refusal is invisible from the sync side: `Redemptions::settle` swallowed the step failure, and finding the `Permission` took instrumenting edges.rs by hand.
