# one-peer-3h2
> Summary: Workflow notes from the 3h2 worker (pull, one pass).

- The step is far larger than one worker session: pull, one pass, deposits, the walk replacing Open, eight new tests, and about 90 osis-node tests written around uploads, Status and Budget codes (`lose_uploads`, `uploaded`, hostile puts racing an upload). A brief that split 3h2 into pull plus one pass, then the walk, then the test rewrite would have fit.
- Three osis-node tests hang when the change is wrong (`deposit_queue::queued_deposit_after_seed_refresh_spec_sync_5`, two `destruction::`), and libtest has no per-test timeout: the whole run then waits until killed by hand, and no panic message prints. A run that kills at the stall and prints the panics so far would save a rerun.
- Debug output in a test needs `--nocapture` and an env var guard can't be set from a test (`unsafe` is forbidden), so a probe meant editing library code each time.
- Two groups created back to back in a test can share a label ID (`sync_review::self_removals_drop_per_group_spec_permissions_3`); a fresh session does not expect that.
- The test net's `SETTLE_ROUNDS` (2000) makes a looping test run for minutes per test: while chasing loops, lowering it to 200 in the worktree turned each hang into a seven-second failure. A per-test override (or a lower default with a few tests opting up) would save the kill-by-PID dance.
- `OSIS_SYNC_TRACE` truncates each message to 300 characters, so a long PullReply never shows the event you grep for; env-guarded `eprintln!` probes stripped by a script before each commit were the working tool.
- Two parallel forks on disjoint test slices still collided in shared pass code (`encrypt_again`, the test net's upload hooks) and in duplicate fixes (both fixed the same own-deposit validity check); messaging each other the shared commits early helped.
- Rebasing a 45-commit WIP branch onto net-6a conflicted only twice, but a probe edit sharing a file with uncommitted SETTLE_ROUNDS made every commit a revert-commit-reapply dance (scripted in the scratchpad); `git commit --amend -- <dir>` silently took the local SETTLE change along.
- With SETTLE_ROUNDS at 200 a few honest settles may need more (the constant's doc says up to about 210): a "no quiescence" at 200 is not proof of a loop.
- Probes need the node's identity: two nodes print the same lines, and a pointer hash (`self as *const _`) was the quickest tag.
