# rearrival-review
> Summary: Footguns met reviewing the pending re-arrival shortcut.

- `wt claim rearrival` reused a stale local `rearrival` branch (an ancestor of the branch under review): fast-forward to `origin/windlass-rearrival` before reading the diff, or the first `diff --stat origin/main...HEAD` shows another branch's work.
- `LocalPeer::receive` runs `reexamine` after every ingest, so a wake the shortcut skips (a due drift `Wake::At`) is invisible there: probe equivalence through `Engine::ingest` directly.
