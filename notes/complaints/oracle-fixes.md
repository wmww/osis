# oracle-fixes
- Per-branch order harness ranges fail on main too (purge_large 4 of 6 seeds at 463452294800, exhaustive_large 3 of 4 at 357829297202): every check needs a main-vs-branch side-by-side (`tools/bin-at main`) to tell new failures from old, about 20 min per three offsets.
- `eprintln!` in a passing test is swallowed without `--nocapture`: a listing probe printed nothing and looked like "no failures".
- Reviewer: `tools/bin-at` checks main out in the task worktree for its whole build (2-3 min); an edit made meanwhile lands on main's files (and may be built into the "main" binary). Wait for it, or edit nothing until it returns.
