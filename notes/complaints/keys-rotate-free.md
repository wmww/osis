# keys-rotate-free
- `wt claim` gave a cold worktree (wt4): the first `cargo test --workspace --no-run` was a few minutes; nothing else blocked.
- TLC through `grep | head` shows nothing until the run ends (grep buffers into a pipe): a long instance looks hung. Write the log to a file and grep it after.
- A test marker with a trailing period that the file did not have made one Python edit script fail after its earlier replacements had run in memory; nothing was written, so no harm, but a script doing many replacements should assert every marker first.
- Review: `run.sh small rotation/D0_` is far from "under ~2 min each": `D0_nc3` took 832 s at 2 workers, load 20-28, and the D0 small set ran over half an hour.
