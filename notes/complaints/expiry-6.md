# expiry-6
> Summary: Step 6 was scoped as model and engine in one run; the engine half touches every pending path and most node-sync entry code, and stopped at the model.

The brief called the whole of step 6 one task. The model half fits a run; the engine half (Kind::Awaits, wake index, batch passes, inbox, memory, spec, tests) is a task of its own.

`pkill -f 'deps/it-'` matches every worktree's test binaries and the calling shell: stop a run through its background task, never by pattern.

`git checkout -- file` to undo a debug edit discards earlier uncommitted work too; copy the file first. A script run from the session cwd used another worktree: `cd` inside it.
