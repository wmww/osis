# listener-3
- The kit workspace (`libs/kit`) builds its own target cold in a worktree that only ever built the core workspace: several minutes at load 30 before its first test.
- Rewriting ~300 test call sites by hand was most of the task; a script inserting `stamp.` at the compiler's E0609 locations did the mechanical third in one pass (worth keeping in mind for field moves).
