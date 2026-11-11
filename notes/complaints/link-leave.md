# link-leave
- The repro's no-host world could not pass for a reason unrelated to the issue: a no-host leaver never confirms its removal (issues/leaving-not-confirmed-after-rotation.md) and keeps dialing. Took a debug-print trace through stream, shared set and judge code to see that a first draft (the sharer leaving its own K, since `edges_at` lists record edges) was the cause of the first failure, then this. A repro carrying a known blocker should say so in its comment.
- `Core::me` is private while `Engine::me` panics; `account_tid` is the one to use from node-sync.
- `wt claim link-leave` for a branch already claimed by this worktree exited 128 with no message; the worktree was fine.
- Review: after rebasing onto main the branch did not compile: `SyncEngine::test_copy` (sync/testing.rs) is an exhaustive struct literal, so a new SyncEngine field must be copied there too.
- Review: the gate's spec_map --gaps stage stopped on the new MUST: a new MUST sentence needs a RULES anchor in tools/spec_map.py and a test citing it; run `python3 tools/spec_map.py --gaps` before handing off.
