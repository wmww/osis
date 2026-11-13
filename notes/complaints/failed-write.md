# failed-write
> Summary: workflow mishaps met on the failed-write branch.

- A `git add -A` wip commit swept in temporary `PROBE_BT` backtrace prints (store `memory.rs`, a node test); caught before the final commit. Probe in a scratch copy or check `git diff` before any wip commit.
- `cargo test -p osis-node` with filters still links the whole `it` binary (about 3 min after a store change); a probe loop through osis-store costs that each round.
