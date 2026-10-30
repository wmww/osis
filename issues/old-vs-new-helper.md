# No helper for old-vs-new comparisons
> Summary: simplification and fix branches compare behaviour or instruction counts against the base commit by swapping sources back and forth in their worktree (four agents: eph-simplify, retention-simplify, retention-residuals, order-gone), which risks mixed builds and loses work. A `tools/` helper that builds a given commit's test binary (dev or release) into a scratch copy, without touching the worktree's files, would make differentials and `tools/icount` comparisons one command.
> Tags: tests
