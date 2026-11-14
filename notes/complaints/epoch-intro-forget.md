# epoch-intro-forget
- No debugger (gdb/lldb/perf) on the box: a hung debug test was located only by eprintln of backtraces per transaction and per commit.
- The first repro (a team not listed in g) hung `settle` for 10+ minutes instead of failing: `SETTLE_ROUNDS`/200k messages is no bound in time when each step is a sampled index check. See issues/released-team-unlisted-label-loop.md.
