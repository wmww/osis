# net-3i complaints
> Summary: Workflow snags met while building 3i1.

- The step was far too large for one branch (wire, both session engines, the hub store's logs, replication, sim adversaries, spec); split into 3i1-3i3 after a survey. Four parallel opus agents on disjoint crates in one worktree worked well.
- A debug `eprintln!` locking `hub_store()` twice in one expression deadlocked a test binary silently (the mutex is not re-entrant); cost ten minutes of waiting before stopping it.
- Finding why a test passed on main took a second worktree and backtrace prints: the row's removal came from an incidental wake, not the stated rule. A sim or test hook naming who removed a row would have saved that.
- `wt release` of a throwaway worktree took over two minutes (moved to background).
- Review: the branch arrived with `tools/spec_map.py --gaps` failing (four RULES anchors naming removed spec text); the instant checks were not run before handing over.
- Review: replacing a per-label log length with node-log counts weakens "nothing logged" checks silently: an entry's earlier event is replaced by its next, so only the log end (`Net::log_end`) shows a new event.
