# growth
- Attributing store commits to a module took a temporary backtrace probe in `pager::commit` plus a thread-local "which node is stepping" set in the harness; a cheap `costs::count_by` per transaction caller (or per module) would have answered it in one run.
- `World` steps every node on one thread, so thread-local cost counters mix nodes; per-node attribution needs the harness to say which node it is stepping.
- The growth tests take several seconds each (60+ writes, each waiting out the tombstone lifetime in simulated time): close to the per-test budget under load.
- `sync-rebuild` moved on while this branch was open; diffs against it showed everyone's changes until diffed against the branch's own base.
