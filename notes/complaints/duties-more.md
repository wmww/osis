# duties-more
- The brief's `git rebase sync-rebuild` from lost-e2e conflicted: sync-rebuild carried lost-e2e's commits rewritten (new hashes). With no commits of my own yet, `git reset --hard sync-rebuild` was the whole catch-up.
- The harness's `run` looks an hour ahead (`HORIZON_MS`): once a keep bound sets a wake, `run` jumps the clock to it, so a test about a bound an hour out must set `w.horizon_ms` lower or it tests the wrong moment (retention.rs). Tests that passed only because nothing woke hide this.
