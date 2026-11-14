# sync-holder-read
- The differential's failure shows what a node reads, not why: finding that a stale stream position survived a shred took ad hoc eprintln tracing (opens open/drop, streams joined) keyed by a node index the harness does not expose to the product. An opt-in per-node trace of member joins/leaves with their rejoin cursor would have made it one run.
- Seed 188669321645, noted as failing on every replay, passes at b36b9f3c5 with and without this fix.
- osis-engine's `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` and `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6` still fail on sync-rebuild; this branch does not touch the engine.
