# double-import
- Load hit 150 from other agents' oracles: a one-test incremental build took 14 min (normally 20 s).
- A test passing captures its eprintln: debug output needs `--nocapture`, cost one extra 14-min round trip.
- `LocalPeer::sync_all` after a move ships the imports everywhere; for order tests deliver by hand from the start.
- rustc runs SCHED_IDLE here (`ps` NI "-"): a concurrent 300-seed sim sweep at normal priority starved a two-file engine rebuild for 30+ min (rustc got ~1 s CPU per minute). notes/build.md says there is no idle-priority penalty; on this box there is.
- Review: `--test it <filter>` piped to `grep | tail -5` showed only the empty binaries' result lines (the filter runs every crate's `it`); grep for `ok. 1 passed` instead.
