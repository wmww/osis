# sig-once
- Measuring "before" with tools/icount needs a second build of the old source: no second checkout may share target/, so the old files were checked out in place over a wip commit and rebuilt (two full osis `it` links, ~3 min each).
- `osis_base::costs` counts are per thread; attributing a verify to a node in the node `Net` harness (all nodes on one thread) needed throwaway backtrace prints.
