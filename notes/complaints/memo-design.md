# memo-design
> Summary: footguns met while measuring and changing osis_base::memo.

- A command started with a trailing `&` inside a foreground Bash call has no task ID, so `claudewait` cannot wait on it; it took a Monitor until-loop to learn when it ended. Start long measurements with `run_in_background`.
- Test binaries panic on an unknown `OSIS_*` variable (core/base/testenv-known.txt): a throwaway counter switch needs a line there too, and that line must not be committed.
- The policy check lists the files allowed to hold world-copy hooks by path (tools/policy.py `COPY_DEFS`), so moving `memo.rs` to `memo/mod.rs` broke it until the list was updated.
- osis-node `it` misses a dropped stamp in the held set (no test failed when `mark_counted` stamped nothing): a stamp needs a unit test per key, as `held_reads_move_with_what_they_read` now does.
- Review: valgrind is not installed on this box although the issue's Method names callgrind; `tools/cpuprof` (inclusive shares) answered instead.
