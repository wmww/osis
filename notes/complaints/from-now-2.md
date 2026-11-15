# from-now-2
- Each planted-fault probe of an osis-engine lib test rebuilds the engine's test binary (about 2 min at load 20): six probes cost more than the tests. A per-fault env switch would not be better (code paths in tests); batching the probes into one background script helped.
- `held_parts` lists versions too ("listed or not"): a test of what a node lists must filter by `listed_at`; easy to assert the wrong thing first.
- No end-to-end check of a grant without history exists above the engine (the sync side is not built): an osis-chat test of it reads nothing yet, so it is committed ignored.
- Review: a newcomer test passed for the wrong reason: `synced(3)` plus `sync_all` after a write hands the future newcomer that write raw, before any cut. Write pre-cut content after the last `sync_all` and deliver it to the others by hand.
- Review: finding why an osis-chat test reads nothing needed a temporary engine eprintln (no osis-level view of what a node holds pending and why).
- Review 2: a `git commit -a` for an unrelated issue edit swept in uncommitted test work; commit the test work (wip) before any other commit.
- Review 2: the streamed `covered` and its oracle disagreed (Some(false) vs None) on a body with an expiry neither held nor value-less beside a snapshot not held; only a random differential calling `covered` on dropped snapshots reached it.
- Rebase: the `from-now-2` ref pointed at the first review's tip; the second review's commits sat detached in another worktree. Check the claimed ref against the reported tip before rebasing.
- Rebase: a test plant named only in prose ("no roles secrets in history entries") is easy to plant half (the history box, not the rotation's own entry) and see 0 failures; the plants' exact sites are written nowhere.
