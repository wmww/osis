# sync-regrant-fail
- `eprintln!` traces in tests show only for failing tests or with `-- --nocapture`; a passing run with traces printed nothing and briefly looked like the code path never ran.
- `git apply` of a whole-tree patch is atomic: one already-applied file fails it all; `--include=<path>` applies part.
- osis-engine `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` and `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6` still fail on sync-rebuild (KNOWN).
