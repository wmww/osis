# test-audit complaints
- Agent shells run at nice 12: every wall measurement competes with other agents' nice-0 builds; `tools/heavy` blocks only all-core runs, so a "locked" build or test still ran beside load 20-37 of builds. Wall numbers here carry their load.
- Rebasing a long-measured branch: `aa4592a6`, the commit notes/build.md cites for the 1900 CPU-s figure, is not on main (rewritten history); its twin is daec95654, found by message.
- A cold build of an old revision in a second worktree took 20 min at load 30-65.
- The heavy lock was held by others for 5-10 min at a time; a measuring task spends much of its wall waiting.
- `cpuprof` exits non-zero on a passing run (its report script fails on a sample file from a child process: `rsplit(":")` with no colon).
