# unmerge-noops
- `tools/icount` printed `INSTR unavailable`: `/proc/sys/kernel/perf_event_paranoid` is 4 on the box, so perf_event_open is refused even unsandboxed. Counted with `valgrind --tool=callgrind` instead (about 50x slower). notes/testing.md says icount works here; it does not now.
- I ran `git checkout -- <file>` to drop a probe and lost real edits in that file too. Put probes in their own wip commit, or keep them in a file of their own.
- The brief listed four no-op rebuilds; a fifth one sat behind the first: dropping the invalid part at the end of the transaction (`drop_invalid`) rebuilt the aspect again. Only the scale test's piece count showed it.
