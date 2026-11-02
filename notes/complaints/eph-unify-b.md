# eph-unify-b
> Summary: Worker complaints from the eph-unify step B branch (split into B1, built, and B2).

- Step B as briefed (swap engine and lane, delete `Remote`, migrate ~4900 lines of lane tests) is several branches of work; the brief's own escape hatch was needed. The reading list alone (remote.rs 1945, sync/ephemeral.rs 1795 lines, the issue 50 KB) took a large share of one agent's context before any edit.
- `Faults::forbid_writes` reports only `Backend(Fault)` at commit: finding which row went durable took a temporary backtrace print in `Transaction::cat_put_to`. A debug hook naming the first forbidden key would save that.
- Review: `wt` was not on PATH (plugin bin at ~/.claude/plugins/cache/wmww-agent-skills/reasonable-rust-builds/*/bin); used by full path. A backgrounded `( ... ) &` group without `cd` wrote logs into another agent's worktree (wt1); cleaned.
