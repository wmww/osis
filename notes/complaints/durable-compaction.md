# durable-compaction
- Turning compaction on for durable data changes the world of about 30 node tests that never meant to test compaction (three small writes on one register now compact): each needs its expectation re-derived by hand. A suite-wide way to see "what changed because a snapshot exists" would have saved hours.
- `Engine::replaced` (replace::replaced) can say a partly erased sequence insert is not replaced at its author but is at another node (deletion::snapshot_falls_rightless_one_covers_*); the own-live-body rule leans on it.
- Debugging needed env-var probes in engine code (removed); a cost-span breakdown per window (`costs::take`) was the most useful tool.
- `wt claim` handed out a worktree another branch had just released (fine), but a probe of main needed a second worktree and a full build (about 1 min warm).
- Re-deriving the tests turned up five real bugs the "nothing compacts on its own" world hid (frontier hole after forgetting, snapshot headers never forgotten, carrier chains, relink ignoring snapshots, served entries whose bytes were dropped); most showed only as a count off by one. Printing the commits held per aspect (kind, author, held) was the fastest way in every case.
- `cargo test -p osis-node --test it a:: b::` is refused (one filter only); `-- a:: b::` works.
- A quick "is this my change?" toggle (an env check in engine code, removed after) was cheaper than a second worktree build of the base commit.
