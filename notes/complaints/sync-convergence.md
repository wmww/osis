# sync-convergence
- The worktree the session started in (wt5) was claimed by another agent's branch (cleanup-tools-2) mid-task: its HEAD moved under me. Claimed my own (`wt claim`); briefs that name a worktree should say to claim one.
- `Script` dropped at the end of `play`, so a failed check after play printed no script; `play` now returns it.
- A shrink-termination test that walked every chain of `Step::simpler` cost 14 G instructions; a decreasing measure checks the same in microseconds.
- Review: a `catch_unwind` around an oracle check hid where a panic came from: the "planted" panic was the unplanted check failing one line earlier (handing commits directly gives every engine plaintext, so non-reader clauses can't be tested with full delivery). Read the backtrace's test line before trusting a caught message.
- `tools/icount` run from `core/sync` with a relative binary path counts 0 instructions silently (exec failed); use an absolute path.
