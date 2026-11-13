# test-optimizer-2
- The cold first build of a fresh worktree took 16 min at load 40 (wt5 had no warm target).
- A planted rollback removal in `Engine::read` passed every engine test: nothing checked that a probe's changes are undone (now `engine::tests::a_read_changes_nothing`).
- A whole-binary cpuprof needs its own symbolizing script to split a function's cost by phase or caller; `cpuprof_report.py` only filters by one frame. Kept in the task's scratch dir, worth a `--callers`/`--under` mode.
