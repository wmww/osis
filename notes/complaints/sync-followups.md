# sync-followups
- The removal-notice repro needed time advanced past `SETTLE_MS`: `World::run` moves no clock, so an admin who learned a sync-only holder's card "just now" never copies it under the label, and a later admin cannot reach the holder at all. A test that only calls `w.run()` reads this as a missing delivery.
- `World::run` accepts invite requests by itself, so a notice a node only admits as an invite request looks admitted in tests. Nothing in the test's output says so.
- `git checkout --theirs` during a rebase takes the commit being replayed (the branch's own), not main: it nearly dropped main's forged-chunk-list changes to large.rs. `git checkout -m <file>` restores the conflict.
