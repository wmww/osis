# listener-3
- The kit workspace (`libs/kit`) builds its own target cold in a worktree that only ever built the core workspace: several minutes at load 30 before its first test.
- Rewriting ~300 test call sites by hand was most of the task; a script inserting `stamp.` at the compiler's E0609 locations did the mechanical third in one pass (worth keeping in mind for field moves).
- Review: the brief assumed kept parts leave by a timer; a value aspect's keep bound has none (only signals' do), so that gap stays open (issues/keep-bound-not-told.md). Worth checking a premise in the code before briefing a fix around it.
