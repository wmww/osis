# sync-integrate-1
- The base moved four times during the task (streams, driver, status, convergence); each rebase hit the same files (engine facade, inbox, read, dead_pub_allow). Rebasing early, before the big rewrite, saved most of it.
- Security rules arrived as three successive versions while I built the first (path filter, deferral, signed epochs); the honest-flow counterexample (an epoch no step ever bears) settled it. A quick model check before briefing would have caught it.
- Removing `set_syncing` touched ~60 engine test sites and a dead dimension of the order harness: removed concepts linger longest in test harnesses.
- `tools/policy.py` and `cargo clippy` both flag only at the end; running policy right after removing a pub fn saves a round.
- Two engine tests fail on the base (`order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5`, `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6`), already in issues; easy to mistake for one's own regression.
- (review) Replacing the inbox's fake-Ground tests with pure-core rule tests dropped every test of the deliveries rules (re-send at expiry, no reseal at restart, stop once the recipient opens a named sync ID): a pure-core refactor should list the rules left without a pure function and keep a node-level test for each. Two restored in keep.rs; the open-by-recipient stop is still untested.
- (review) `git checkout <file>` to undo a mutation also undid my own uncommitted fix in the same file: copy the file aside before mutating, as for the others.
