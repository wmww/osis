# eph-window-slow
- `tools/bin-at` binaries read core/base/testenv-known.txt from the worktree at run time, so a pre-item-186 binary refuses its own `OSIS_EPH_THREADS` (and a new one refuses old names): add the name to the file for the run, then `git checkout` it.
- A test binary picked as any `it-*` that lists the test can be an old one after bin-at: bin-at's old builds land in the same `target/debug/deps` under other hashes; pick by mtime (`ls -t`) or copy straight after building.
- The "hang" and the "collapse" were both CPU starvation of a nice-19 run (no product change); wall-time progress lines alone could not tell that apart from a regression.
- Review: a deadlocked seed still holds the exit for the full `TRACE_GRACE_SECS` (it never reaches a checkpoint), so a deadlock probe at a 2 s limit takes 12 s; expected, but surprising at first.
