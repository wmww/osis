# sync-cost
- Finding which container moved an `Effects` key took a throwaway probe: memo `Table`s carry no name, so a due key cannot say what moved it. A debug-only name per `Stamps` (or a costs counter per moved table) would have made the whole study a counter read.
- `osis-engine --test it` fails two tests on sync-rebuild 1094cf3d1 itself (`order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5`, `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6`); checking that needed a detached checkout, since `sync-rebuild` is checked out in another worktree.
