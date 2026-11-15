# late-joiner
- `git revert -q` is not an option: the revert silently did not happen and a "before" probe run measured the fixed tree. Check `git log -1` after any revert.
- `git checkout <file>` to undo a mutation probe also undid an uncommitted real edit in the same file; commit before probing (the preamble says so; it bit anyway).
- No test hook exposed read's verdict per (S, commit); a must-hold-with-no-entry probe needs one (`Node::verdict`, not committed) plus a per-node id for traces. A committed, env-gated probe at each quiet would let the next agent rerun this in one command.
