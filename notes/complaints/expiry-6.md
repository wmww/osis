# expiry-6
> Summary: Step 6 was scoped as model and engine in one run; the engine half touches every pending path and most node-sync entry code, and stopped at the model.

The brief called the whole of step 6 one task. The model half fits a run; the engine half (Kind::Awaits, wake index, batch passes, inbox, memory, spec, tests) is a task of its own.

`pkill -f 'deps/it-'` matches every worktree's test binaries and the calling shell: stop a run through its background task, never by pattern.

`git checkout -- file` to undo a debug edit discards earlier uncommitted work too; copy the file first. A script run from the session cwd used another worktree: `cd` inside it.

Reviewer: `relay_differential_large` and the order harness run only via `test_select --run`; the worker's commit left two real failures to them (a thrown-out commit keyed on one record; the relay harness pushing entries no host holds). A `_large` that fails every seed is cheaper to catch before review: run one derived property per changed harness.

Reviewer: a wake on a monotonic counter loops through a commit's own box re-read: wake comparisons are by value (the shape of what is held), not a generation.
